rule TTP_XOR_QUAD_CurrentVersionRun_b581 {
  strings:
    $key_b581 = { e6 ee [2] c2 e0 [2] e9 cc [2] c7 ee [2] d3 f5 [2] dc ef [2] c2 f2 [2] c0 f3 [2] db f5 [2] c7 f2 [2] db dd }

  condition:
    any of them
}