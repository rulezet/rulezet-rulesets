rule TTP_XOR_QUAD_CurrentVersionRun_a39e {
  strings:
    $key_a39e = { f0 f1 [2] d4 ff [2] ff d3 [2] d1 f1 [2] c5 ea [2] ca f0 [2] d4 ed [2] d6 ec [2] cd ea [2] d1 ed [2] cd c2 }

  condition:
    any of them
}