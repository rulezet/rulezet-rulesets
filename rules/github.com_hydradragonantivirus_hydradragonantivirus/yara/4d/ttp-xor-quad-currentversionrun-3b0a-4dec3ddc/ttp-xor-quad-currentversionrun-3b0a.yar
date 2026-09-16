rule TTP_XOR_QUAD_CurrentVersionRun_3b0a {
  strings:
    $key_3b0a = { 68 65 [2] 4c 6b [2] 67 47 [2] 49 65 [2] 5d 7e [2] 52 64 [2] 4c 79 [2] 4e 78 [2] 55 7e [2] 49 79 [2] 55 56 }

  condition:
    any of them
}