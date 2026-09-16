rule TTP_XOR_QUAD_CurrentVersionRun_42a9 {
  strings:
    $key_42a9 = { 11 c6 [2] 35 c8 [2] 1e e4 [2] 30 c6 [2] 24 dd [2] 2b c7 [2] 35 da [2] 37 db [2] 2c dd [2] 30 da [2] 2c f5 }

  condition:
    any of them
}