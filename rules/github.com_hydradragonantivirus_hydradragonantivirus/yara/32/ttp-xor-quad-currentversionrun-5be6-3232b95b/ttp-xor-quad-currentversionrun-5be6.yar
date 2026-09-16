rule TTP_XOR_QUAD_CurrentVersionRun_5be6 {
  strings:
    $key_5be6 = { 08 89 [2] 2c 87 [2] 07 ab [2] 29 89 [2] 3d 92 [2] 32 88 [2] 2c 95 [2] 2e 94 [2] 35 92 [2] 29 95 [2] 35 ba }

  condition:
    any of them
}