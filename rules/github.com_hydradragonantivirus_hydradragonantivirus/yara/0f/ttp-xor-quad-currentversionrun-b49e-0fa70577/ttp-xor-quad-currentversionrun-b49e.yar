rule TTP_XOR_QUAD_CurrentVersionRun_b49e {
  strings:
    $key_b49e = { e7 f1 [2] c3 ff [2] e8 d3 [2] c6 f1 [2] d2 ea [2] dd f0 [2] c3 ed [2] c1 ec [2] da ea [2] c6 ed [2] da c2 }

  condition:
    any of them
}