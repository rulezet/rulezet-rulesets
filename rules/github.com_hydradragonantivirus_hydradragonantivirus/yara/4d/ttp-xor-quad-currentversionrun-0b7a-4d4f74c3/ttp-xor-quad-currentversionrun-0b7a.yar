rule TTP_XOR_QUAD_CurrentVersionRun_0b7a {
  strings:
    $key_0b7a = { 58 15 [2] 7c 1b [2] 57 37 [2] 79 15 [2] 6d 0e [2] 62 14 [2] 7c 09 [2] 7e 08 [2] 65 0e [2] 79 09 [2] 65 26 }

  condition:
    any of them
}