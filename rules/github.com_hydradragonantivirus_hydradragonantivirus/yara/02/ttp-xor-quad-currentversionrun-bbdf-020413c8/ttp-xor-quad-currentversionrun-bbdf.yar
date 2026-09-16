rule TTP_XOR_QUAD_CurrentVersionRun_bbdf {
  strings:
    $key_bbdf = { e8 b0 [2] cc be [2] e7 92 [2] c9 b0 [2] dd ab [2] d2 b1 [2] cc ac [2] ce ad [2] d5 ab [2] c9 ac [2] d5 83 }

  condition:
    any of them
}