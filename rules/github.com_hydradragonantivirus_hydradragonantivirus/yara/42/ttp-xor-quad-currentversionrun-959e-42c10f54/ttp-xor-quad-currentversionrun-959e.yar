rule TTP_XOR_QUAD_CurrentVersionRun_959e {
  strings:
    $key_959e = { c6 f1 [2] e2 ff [2] c9 d3 [2] e7 f1 [2] f3 ea [2] fc f0 [2] e2 ed [2] e0 ec [2] fb ea [2] e7 ed [2] fb c2 }

  condition:
    any of them
}