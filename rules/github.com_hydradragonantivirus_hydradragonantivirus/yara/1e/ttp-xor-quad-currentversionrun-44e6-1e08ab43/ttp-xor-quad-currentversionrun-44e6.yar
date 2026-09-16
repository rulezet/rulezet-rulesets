rule TTP_XOR_QUAD_CurrentVersionRun_44e6 {
  strings:
    $key_44e6 = { 17 89 [2] 33 87 [2] 18 ab [2] 36 89 [2] 22 92 [2] 2d 88 [2] 33 95 [2] 31 94 [2] 2a 92 [2] 36 95 [2] 2a ba }

  condition:
    any of them
}