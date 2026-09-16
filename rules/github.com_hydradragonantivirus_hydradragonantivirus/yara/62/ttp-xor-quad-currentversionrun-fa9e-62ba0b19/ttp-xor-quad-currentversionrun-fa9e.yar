rule TTP_XOR_QUAD_CurrentVersionRun_fa9e {
  strings:
    $key_fa9e = { a9 f1 [2] 8d ff [2] a6 d3 [2] 88 f1 [2] 9c ea [2] 93 f0 [2] 8d ed [2] 8f ec [2] 94 ea [2] 88 ed [2] 94 c2 }

  condition:
    any of them
}