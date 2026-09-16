rule TTP_XOR_QUAD_CurrentVersionRun_0f9e {
  strings:
    $key_0f9e = { 5c f1 [2] 78 ff [2] 53 d3 [2] 7d f1 [2] 69 ea [2] 66 f0 [2] 78 ed [2] 7a ec [2] 61 ea [2] 7d ed [2] 61 c2 }

  condition:
    any of them
}