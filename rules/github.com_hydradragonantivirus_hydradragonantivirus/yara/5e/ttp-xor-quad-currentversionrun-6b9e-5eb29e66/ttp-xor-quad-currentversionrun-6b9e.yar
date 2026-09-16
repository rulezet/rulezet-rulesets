rule TTP_XOR_QUAD_CurrentVersionRun_6b9e {
  strings:
    $key_6b9e = { 38 f1 [2] 1c ff [2] 37 d3 [2] 19 f1 [2] 0d ea [2] 02 f0 [2] 1c ed [2] 1e ec [2] 05 ea [2] 19 ed [2] 05 c2 }

  condition:
    any of them
}