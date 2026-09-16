rule TTP_XOR_QUAD_CurrentVersionRun_b2bc {
  strings:
    $key_b2bc = { e1 d3 [2] c5 dd [2] ee f1 [2] c0 d3 [2] d4 c8 [2] db d2 [2] c5 cf [2] c7 ce [2] dc c8 [2] c0 cf [2] dc e0 }

  condition:
    any of them
}