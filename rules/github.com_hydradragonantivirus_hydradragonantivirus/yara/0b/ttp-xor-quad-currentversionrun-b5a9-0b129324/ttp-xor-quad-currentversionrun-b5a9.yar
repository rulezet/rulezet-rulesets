rule TTP_XOR_QUAD_CurrentVersionRun_b5a9 {
  strings:
    $key_b5a9 = { e6 c6 [2] c2 c8 [2] e9 e4 [2] c7 c6 [2] d3 dd [2] dc c7 [2] c2 da [2] c0 db [2] db dd [2] c7 da [2] db f5 }

  condition:
    any of them
}