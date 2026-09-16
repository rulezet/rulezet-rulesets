rule TTP_XOR_QUAD_CurrentVersionRun_94df {
  strings:
    $key_94df = { c7 b0 [2] e3 be [2] c8 92 [2] e6 b0 [2] f2 ab [2] fd b1 [2] e3 ac [2] e1 ad [2] fa ab [2] e6 ac [2] fa 83 }

  condition:
    any of them
}