rule TTP_XOR_QUAD_CurrentVersionRun_6f9e {
  strings:
    $key_6f9e = { 3c f1 [2] 18 ff [2] 33 d3 [2] 1d f1 [2] 09 ea [2] 06 f0 [2] 18 ed [2] 1a ec [2] 01 ea [2] 1d ed [2] 01 c2 }

  condition:
    any of them
}