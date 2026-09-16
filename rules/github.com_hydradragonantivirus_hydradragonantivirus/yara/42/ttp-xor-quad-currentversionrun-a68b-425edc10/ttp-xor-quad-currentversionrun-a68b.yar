rule TTP_XOR_QUAD_CurrentVersionRun_a68b {
  strings:
    $key_a68b = { f5 e4 [2] d1 ea [2] fa c6 [2] d4 e4 [2] c0 ff [2] cf e5 [2] d1 f8 [2] d3 f9 [2] c8 ff [2] d4 f8 [2] c8 d7 }

  condition:
    any of them
}