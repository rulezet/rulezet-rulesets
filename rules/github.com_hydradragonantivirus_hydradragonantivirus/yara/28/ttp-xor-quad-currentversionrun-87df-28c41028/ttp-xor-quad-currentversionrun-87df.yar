rule TTP_XOR_QUAD_CurrentVersionRun_87df {
  strings:
    $key_87df = { d4 b0 [2] f0 be [2] db 92 [2] f5 b0 [2] e1 ab [2] ee b1 [2] f0 ac [2] f2 ad [2] e9 ab [2] f5 ac [2] e9 83 }

  condition:
    any of them
}