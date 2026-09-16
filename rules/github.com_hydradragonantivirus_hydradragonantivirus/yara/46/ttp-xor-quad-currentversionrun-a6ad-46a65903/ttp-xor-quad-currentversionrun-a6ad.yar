rule TTP_XOR_QUAD_CurrentVersionRun_a6ad {
  strings:
    $key_a6ad = { f5 c2 [2] d1 cc [2] fa e0 [2] d4 c2 [2] c0 d9 [2] cf c3 [2] d1 de [2] d3 df [2] c8 d9 [2] d4 de [2] c8 f1 }

  condition:
    any of them
}