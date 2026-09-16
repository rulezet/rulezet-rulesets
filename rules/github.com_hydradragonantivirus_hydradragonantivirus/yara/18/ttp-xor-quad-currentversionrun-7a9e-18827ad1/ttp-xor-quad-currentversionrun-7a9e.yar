rule TTP_XOR_QUAD_CurrentVersionRun_7a9e {
  strings:
    $key_7a9e = { 29 f1 [2] 0d ff [2] 26 d3 [2] 08 f1 [2] 1c ea [2] 13 f0 [2] 0d ed [2] 0f ec [2] 14 ea [2] 08 ed [2] 14 c2 }

  condition:
    any of them
}