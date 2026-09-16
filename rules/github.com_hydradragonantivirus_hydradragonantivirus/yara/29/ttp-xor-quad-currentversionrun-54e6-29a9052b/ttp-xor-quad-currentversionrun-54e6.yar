rule TTP_XOR_QUAD_CurrentVersionRun_54e6 {
  strings:
    $key_54e6 = { 07 89 [2] 23 87 [2] 08 ab [2] 26 89 [2] 32 92 [2] 3d 88 [2] 23 95 [2] 21 94 [2] 3a 92 [2] 26 95 [2] 3a ba }

  condition:
    any of them
}