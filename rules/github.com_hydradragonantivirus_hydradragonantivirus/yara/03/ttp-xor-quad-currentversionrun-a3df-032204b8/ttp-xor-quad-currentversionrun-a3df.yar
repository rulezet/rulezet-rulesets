rule TTP_XOR_QUAD_CurrentVersionRun_a3df {
  strings:
    $key_a3df = { f0 b0 [2] d4 be [2] ff 92 [2] d1 b0 [2] c5 ab [2] ca b1 [2] d4 ac [2] d6 ad [2] cd ab [2] d1 ac [2] cd 83 }

  condition:
    any of them
}