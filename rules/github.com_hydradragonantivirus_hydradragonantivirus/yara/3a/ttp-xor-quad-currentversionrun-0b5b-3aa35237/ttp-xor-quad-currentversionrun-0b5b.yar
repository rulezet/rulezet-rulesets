rule TTP_XOR_QUAD_CurrentVersionRun_0b5b {
  strings:
    $key_0b5b = { 58 34 [2] 7c 3a [2] 57 16 [2] 79 34 [2] 6d 2f [2] 62 35 [2] 7c 28 [2] 7e 29 [2] 65 2f [2] 79 28 [2] 65 07 }

  condition:
    any of them
}