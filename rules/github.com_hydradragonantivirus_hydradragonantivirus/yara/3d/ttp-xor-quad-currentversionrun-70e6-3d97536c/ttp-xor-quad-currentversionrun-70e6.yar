rule TTP_XOR_QUAD_CurrentVersionRun_70e6 {
  strings:
    $key_70e6 = { 23 89 [2] 07 87 [2] 2c ab [2] 02 89 [2] 16 92 [2] 19 88 [2] 07 95 [2] 05 94 [2] 1e 92 [2] 02 95 [2] 1e ba }

  condition:
    any of them
}