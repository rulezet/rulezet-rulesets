rule TTP_XOR_QUAD_CurrentVersionRun_bd94 {
  strings:
    $key_bd94 = { ee fb [2] ca f5 [2] e1 d9 [2] cf fb [2] db e0 [2] d4 fa [2] ca e7 [2] c8 e6 [2] d3 e0 [2] cf e7 [2] d3 c8 }

  condition:
    any of them
}