rule TTP_XOR_QUAD_CurrentVersionRun_4ae6 {
  strings:
    $key_4ae6 = { 19 89 [2] 3d 87 [2] 16 ab [2] 38 89 [2] 2c 92 [2] 23 88 [2] 3d 95 [2] 3f 94 [2] 24 92 [2] 38 95 [2] 24 ba }

  condition:
    any of them
}