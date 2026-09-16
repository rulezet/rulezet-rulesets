rule TTP_XOR_QUAD_CurrentVersionRun_3c0a {
  strings:
    $key_3c0a = { 6f 65 [2] 4b 6b [2] 60 47 [2] 4e 65 [2] 5a 7e [2] 55 64 [2] 4b 79 [2] 49 78 [2] 52 7e [2] 4e 79 [2] 52 56 }

  condition:
    any of them
}