rule TTP_XOR_QUAD_CurrentVersionRun_b69e {
  strings:
    $key_b69e = { e5 f1 [2] c1 ff [2] ea d3 [2] c4 f1 [2] d0 ea [2] df f0 [2] c1 ed [2] c3 ec [2] d8 ea [2] c4 ed [2] d8 c2 }

  condition:
    any of them
}