rule TTP_XOR_QUAD_CurrentVersionRun_3b9e {
  strings:
    $key_3b9e = { 68 f1 [2] 4c ff [2] 67 d3 [2] 49 f1 [2] 5d ea [2] 52 f0 [2] 4c ed [2] 4e ec [2] 55 ea [2] 49 ed [2] 55 c2 }

  condition:
    any of them
}