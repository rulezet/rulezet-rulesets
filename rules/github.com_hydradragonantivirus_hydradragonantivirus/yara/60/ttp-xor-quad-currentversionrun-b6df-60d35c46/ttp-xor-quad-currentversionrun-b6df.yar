rule TTP_XOR_QUAD_CurrentVersionRun_b6df {
  strings:
    $key_b6df = { e5 b0 [2] c1 be [2] ea 92 [2] c4 b0 [2] d0 ab [2] df b1 [2] c1 ac [2] c3 ad [2] d8 ab [2] c4 ac [2] d8 83 }

  condition:
    any of them
}