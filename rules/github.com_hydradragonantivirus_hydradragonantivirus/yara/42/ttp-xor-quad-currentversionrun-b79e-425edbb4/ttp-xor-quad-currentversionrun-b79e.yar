rule TTP_XOR_QUAD_CurrentVersionRun_b79e {
  strings:
    $key_b79e = { e4 f1 [2] c0 ff [2] eb d3 [2] c5 f1 [2] d1 ea [2] de f0 [2] c0 ed [2] c2 ec [2] d9 ea [2] c5 ed [2] d9 c2 }

  condition:
    any of them
}