rule TTP_XOR_QUAD_CurrentVersionRun_4591 {
  strings:
    $key_4591 = { 16 fe [2] 32 f0 [2] 19 dc [2] 37 fe [2] 23 e5 [2] 2c ff [2] 32 e2 [2] 30 e3 [2] 2b e5 [2] 37 e2 [2] 2b cd }

  condition:
    any of them
}