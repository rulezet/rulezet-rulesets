rule TTP_XOR_QUAD_CurrentVersionRun_3b4a {
  strings:
    $key_3b4a = { 68 25 [2] 4c 2b [2] 67 07 [2] 49 25 [2] 5d 3e [2] 52 24 [2] 4c 39 [2] 4e 38 [2] 55 3e [2] 49 39 [2] 55 16 }

  condition:
    any of them
}