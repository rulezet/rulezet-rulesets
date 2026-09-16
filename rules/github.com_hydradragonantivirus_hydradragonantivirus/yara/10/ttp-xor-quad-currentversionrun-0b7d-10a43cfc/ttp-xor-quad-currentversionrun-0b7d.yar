rule TTP_XOR_QUAD_CurrentVersionRun_0b7d {
  strings:
    $key_0b7d = { 58 12 [2] 7c 1c [2] 57 30 [2] 79 12 [2] 6d 09 [2] 62 13 [2] 7c 0e [2] 7e 0f [2] 65 09 [2] 79 0e [2] 65 21 }

  condition:
    any of them
}