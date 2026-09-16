rule TTP_XOR_QUAD_CurrentVersionRun_74d1 {
  strings:
    $key_74d1 = { 27 be [2] 03 b0 [2] 28 9c [2] 06 be [2] 12 a5 [2] 1d bf [2] 03 a2 [2] 01 a3 [2] 1a a5 [2] 06 a2 [2] 1a 8d }

  condition:
    any of them
}