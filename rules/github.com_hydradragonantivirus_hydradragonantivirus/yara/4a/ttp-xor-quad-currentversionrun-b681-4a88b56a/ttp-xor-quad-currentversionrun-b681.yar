rule TTP_XOR_QUAD_CurrentVersionRun_b681 {
  strings:
    $key_b681 = { e5 ee [2] c1 e0 [2] ea cc [2] c4 ee [2] d0 f5 [2] df ef [2] c1 f2 [2] c3 f3 [2] d8 f5 [2] c4 f2 [2] d8 dd }

  condition:
    any of them
}