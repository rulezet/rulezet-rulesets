rule TTP_XOR_QUAD_CurrentVersionRun_b29e {
  strings:
    $key_b29e = { e1 f1 [2] c5 ff [2] ee d3 [2] c0 f1 [2] d4 ea [2] db f0 [2] c5 ed [2] c7 ec [2] dc ea [2] c0 ed [2] dc c2 }

  condition:
    any of them
}