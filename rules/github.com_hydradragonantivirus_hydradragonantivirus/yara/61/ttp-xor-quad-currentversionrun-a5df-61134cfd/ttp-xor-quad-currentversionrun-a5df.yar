rule TTP_XOR_QUAD_CurrentVersionRun_a5df {
  strings:
    $key_a5df = { f6 b0 [2] d2 be [2] f9 92 [2] d7 b0 [2] c3 ab [2] cc b1 [2] d2 ac [2] d0 ad [2] cb ab [2] d7 ac [2] cb 83 }

  condition:
    any of them
}