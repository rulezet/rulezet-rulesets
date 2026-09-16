rule TTP_XOR_QUAD_CurrentVersionRun_b5ae {
  strings:
    $key_b5ae = { e6 c1 [2] c2 cf [2] e9 e3 [2] c7 c1 [2] d3 da [2] dc c0 [2] c2 dd [2] c0 dc [2] db da [2] c7 dd [2] db f2 }

  condition:
    any of them
}