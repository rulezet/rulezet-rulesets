rule TTP_XOR_QUAD_CurrentVersionRun_42a3 {
  strings:
    $key_42a3 = { 11 cc [2] 35 c2 [2] 1e ee [2] 30 cc [2] 24 d7 [2] 2b cd [2] 35 d0 [2] 37 d1 [2] 2c d7 [2] 30 d0 [2] 2c ff }

  condition:
    any of them
}