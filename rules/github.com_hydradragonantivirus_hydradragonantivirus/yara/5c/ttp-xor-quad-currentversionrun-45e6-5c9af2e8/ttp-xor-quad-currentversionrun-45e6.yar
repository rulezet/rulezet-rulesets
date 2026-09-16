rule TTP_XOR_QUAD_CurrentVersionRun_45e6 {
  strings:
    $key_45e6 = { 16 89 [2] 32 87 [2] 19 ab [2] 37 89 [2] 23 92 [2] 2c 88 [2] 32 95 [2] 30 94 [2] 2b 92 [2] 37 95 [2] 2b ba }

  condition:
    any of them
}