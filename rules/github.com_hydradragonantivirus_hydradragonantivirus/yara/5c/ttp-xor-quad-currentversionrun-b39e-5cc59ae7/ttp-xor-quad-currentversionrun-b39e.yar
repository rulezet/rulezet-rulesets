rule TTP_XOR_QUAD_CurrentVersionRun_b39e {
  strings:
    $key_b39e = { e0 f1 [2] c4 ff [2] ef d3 [2] c1 f1 [2] d5 ea [2] da f0 [2] c4 ed [2] c6 ec [2] dd ea [2] c1 ed [2] dd c2 }

  condition:
    any of them
}