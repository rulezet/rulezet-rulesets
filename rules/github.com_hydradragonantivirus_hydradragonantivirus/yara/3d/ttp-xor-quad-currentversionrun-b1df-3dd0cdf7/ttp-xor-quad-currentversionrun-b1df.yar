rule TTP_XOR_QUAD_CurrentVersionRun_b1df {
  strings:
    $key_b1df = { e2 b0 [2] c6 be [2] ed 92 [2] c3 b0 [2] d7 ab [2] d8 b1 [2] c6 ac [2] c4 ad [2] df ab [2] c3 ac [2] df 83 }

  condition:
    any of them
}