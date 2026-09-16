rule TTP_XOR_QUAD_CurrentVersionRun_a2df {
  strings:
    $key_a2df = { f1 b0 [2] d5 be [2] fe 92 [2] d0 b0 [2] c4 ab [2] cb b1 [2] d5 ac [2] d7 ad [2] cc ab [2] d0 ac [2] cc 83 }

  condition:
    any of them
}