rule TTP_XOR_QUAD_CurrentVersionRun_7467 {
  strings:
    $key_7467 = { 27 08 [2] 03 06 [2] 28 2a [2] 06 08 [2] 12 13 [2] 1d 09 [2] 03 14 [2] 01 15 [2] 1a 13 [2] 06 14 [2] 1a 3b }

  condition:
    any of them
}