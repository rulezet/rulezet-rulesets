rule TTP_XOR_QUAD_CurrentVersionRun_b3a3 {
  strings:
    $key_b3a3 = { e0 cc [2] c4 c2 [2] ef ee [2] c1 cc [2] d5 d7 [2] da cd [2] c4 d0 [2] c6 d1 [2] dd d7 [2] c1 d0 [2] dd ff }

  condition:
    any of them
}