rule TTP_XOR_QUAD_CurrentVersionRun_549e {
  strings:
    $key_549e = { 07 f1 [2] 23 ff [2] 08 d3 [2] 26 f1 [2] 32 ea [2] 3d f0 [2] 23 ed [2] 21 ec [2] 3a ea [2] 26 ed [2] 3a c2 }

  condition:
    any of them
}