rule TTP_XOR_QUAD_CurrentVersionRun_7479 {
  strings:
    $key_7479 = { 27 16 [2] 03 18 [2] 28 34 [2] 06 16 [2] 12 0d [2] 1d 17 [2] 03 0a [2] 01 0b [2] 1a 0d [2] 06 0a [2] 1a 25 }

  condition:
    any of them
}