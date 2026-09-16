rule TTP_XOR_QUAD_CurrentVersionRun_b2ae {
  strings:
    $key_b2ae = { e1 c1 [2] c5 cf [2] ee e3 [2] c0 c1 [2] d4 da [2] db c0 [2] c5 dd [2] c7 dc [2] dc da [2] c0 dd [2] dc f2 }

  condition:
    any of them
}