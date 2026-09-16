rule TTP_XOR_QUAD_CurrentVersionRun_74e4 {
  strings:
    $key_74e4 = { 27 8b [2] 03 85 [2] 28 a9 [2] 06 8b [2] 12 90 [2] 1d 8a [2] 03 97 [2] 01 96 [2] 1a 90 [2] 06 97 [2] 1a b8 }

  condition:
    any of them
}