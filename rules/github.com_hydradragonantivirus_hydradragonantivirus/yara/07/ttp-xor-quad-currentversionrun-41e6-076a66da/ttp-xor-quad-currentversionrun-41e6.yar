rule TTP_XOR_QUAD_CurrentVersionRun_41e6 {
  strings:
    $key_41e6 = { 12 89 [2] 36 87 [2] 1d ab [2] 33 89 [2] 27 92 [2] 28 88 [2] 36 95 [2] 34 94 [2] 2f 92 [2] 33 95 [2] 2f ba }

  condition:
    any of them
}