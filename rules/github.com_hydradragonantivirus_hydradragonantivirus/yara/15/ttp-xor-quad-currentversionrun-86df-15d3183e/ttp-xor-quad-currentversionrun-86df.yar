rule TTP_XOR_QUAD_CurrentVersionRun_86df {
  strings:
    $key_86df = { d5 b0 [2] f1 be [2] da 92 [2] f4 b0 [2] e0 ab [2] ef b1 [2] f1 ac [2] f3 ad [2] e8 ab [2] f4 ac [2] e8 83 }

  condition:
    any of them
}