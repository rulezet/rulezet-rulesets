rule TTP_XOR_QUAD_CurrentVersionRun_97df {
  strings:
    $key_97df = { c4 b0 [2] e0 be [2] cb 92 [2] e5 b0 [2] f1 ab [2] fe b1 [2] e0 ac [2] e2 ad [2] f9 ab [2] e5 ac [2] f9 83 }

  condition:
    any of them
}