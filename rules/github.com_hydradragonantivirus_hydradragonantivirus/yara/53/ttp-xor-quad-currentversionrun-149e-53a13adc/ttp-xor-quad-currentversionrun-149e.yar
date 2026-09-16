rule TTP_XOR_QUAD_CurrentVersionRun_149e {
  strings:
    $key_149e = { 47 f1 [2] 63 ff [2] 48 d3 [2] 66 f1 [2] 72 ea [2] 7d f0 [2] 63 ed [2] 61 ec [2] 7a ea [2] 66 ed [2] 7a c2 }

  condition:
    any of them
}