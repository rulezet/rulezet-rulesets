rule TTP_XOR_QUAD_CurrentVersionRun_0b77 {
  strings:
    $key_0b77 = { 58 18 [2] 7c 16 [2] 57 3a [2] 79 18 [2] 6d 03 [2] 62 19 [2] 7c 04 [2] 7e 05 [2] 65 03 [2] 79 04 [2] 65 2b }

  condition:
    any of them
}