rule TTP_XOR_QUAD_CurrentVersionRun_bc9e {
  strings:
    $key_bc9e = { ef f1 [2] cb ff [2] e0 d3 [2] ce f1 [2] da ea [2] d5 f0 [2] cb ed [2] c9 ec [2] d2 ea [2] ce ed [2] d2 c2 }

  condition:
    any of them
}