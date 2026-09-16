rule TTP_XOR_QUAD_CurrentVersionRun_93df {
  strings:
    $key_93df = { c0 b0 [2] e4 be [2] cf 92 [2] e1 b0 [2] f5 ab [2] fa b1 [2] e4 ac [2] e6 ad [2] fd ab [2] e1 ac [2] fd 83 }

  condition:
    any of them
}