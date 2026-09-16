rule TTP_XOR_QUAD_CurrentVersionRun_3a9e {
  strings:
    $key_3a9e = { 69 f1 [2] 4d ff [2] 66 d3 [2] 48 f1 [2] 5c ea [2] 53 f0 [2] 4d ed [2] 4f ec [2] 54 ea [2] 48 ed [2] 54 c2 }

  condition:
    any of them
}