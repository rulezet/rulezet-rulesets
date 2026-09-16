rule TTP_XOR_QUAD_CurrentVersionRun_91df {
  strings:
    $key_91df = { c2 b0 [2] e6 be [2] cd 92 [2] e3 b0 [2] f7 ab [2] f8 b1 [2] e6 ac [2] e4 ad [2] ff ab [2] e3 ac [2] ff 83 }

  condition:
    any of them
}