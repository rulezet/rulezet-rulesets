rule TTP_XOR_QUAD_CurrentVersionRun_71e6 {
  strings:
    $key_71e6 = { 22 89 [2] 06 87 [2] 2d ab [2] 03 89 [2] 17 92 [2] 18 88 [2] 06 95 [2] 04 94 [2] 1f 92 [2] 03 95 [2] 1f ba }

  condition:
    any of them
}