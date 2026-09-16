rule TTP_XOR_QUAD_CurrentVersionRun_74e6 {
  strings:
    $key_74e6 = { 27 89 [2] 03 87 [2] 28 ab [2] 06 89 [2] 12 92 [2] 1d 88 [2] 03 95 [2] 01 94 [2] 1a 92 [2] 06 95 [2] 1a ba }

  condition:
    any of them
}