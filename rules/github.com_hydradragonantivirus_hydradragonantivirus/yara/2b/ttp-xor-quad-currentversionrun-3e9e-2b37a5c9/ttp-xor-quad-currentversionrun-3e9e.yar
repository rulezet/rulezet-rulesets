rule TTP_XOR_QUAD_CurrentVersionRun_3e9e {
  strings:
    $key_3e9e = { 6d f1 [2] 49 ff [2] 62 d3 [2] 4c f1 [2] 58 ea [2] 57 f0 [2] 49 ed [2] 4b ec [2] 50 ea [2] 4c ed [2] 50 c2 }

  condition:
    any of them
}