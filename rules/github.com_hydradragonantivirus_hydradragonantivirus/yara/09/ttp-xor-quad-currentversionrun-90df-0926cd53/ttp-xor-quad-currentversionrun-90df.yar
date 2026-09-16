rule TTP_XOR_QUAD_CurrentVersionRun_90df {
  strings:
    $key_90df = { c3 b0 [2] e7 be [2] cc 92 [2] e2 b0 [2] f6 ab [2] f9 b1 [2] e7 ac [2] e5 ad [2] fe ab [2] e2 ac [2] fe 83 }

  condition:
    any of them
}