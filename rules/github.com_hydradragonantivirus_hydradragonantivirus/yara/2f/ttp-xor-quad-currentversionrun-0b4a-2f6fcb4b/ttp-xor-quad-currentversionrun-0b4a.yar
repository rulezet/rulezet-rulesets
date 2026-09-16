rule TTP_XOR_QUAD_CurrentVersionRun_0b4a {
  strings:
    $key_0b4a = { 58 25 [2] 7c 2b [2] 57 07 [2] 79 25 [2] 6d 3e [2] 62 24 [2] 7c 39 [2] 7e 38 [2] 65 3e [2] 79 39 [2] 65 16 }

  condition:
    any of them
}