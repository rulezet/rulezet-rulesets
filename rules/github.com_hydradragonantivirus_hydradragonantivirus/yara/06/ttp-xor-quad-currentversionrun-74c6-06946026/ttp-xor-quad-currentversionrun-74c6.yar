rule TTP_XOR_QUAD_CurrentVersionRun_74c6 {
  strings:
    $key_74c6 = { 27 a9 [2] 03 a7 [2] 28 8b [2] 06 a9 [2] 12 b2 [2] 1d a8 [2] 03 b5 [2] 01 b4 [2] 1a b2 [2] 06 b5 [2] 1a 9a }

  condition:
    any of them
}