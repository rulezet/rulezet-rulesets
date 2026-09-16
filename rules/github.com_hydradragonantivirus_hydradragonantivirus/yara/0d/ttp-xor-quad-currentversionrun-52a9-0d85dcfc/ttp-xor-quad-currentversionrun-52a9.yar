rule TTP_XOR_QUAD_CurrentVersionRun_52a9 {
  strings:
    $key_52a9 = { 01 c6 [2] 25 c8 [2] 0e e4 [2] 20 c6 [2] 34 dd [2] 3b c7 [2] 25 da [2] 27 db [2] 3c dd [2] 20 da [2] 3c f5 }

  condition:
    any of them
}