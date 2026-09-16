rule TTP_XOR_QUAD_CurrentVersionRun_9bdf {
  strings:
    $key_9bdf = { c8 b0 [2] ec be [2] c7 92 [2] e9 b0 [2] fd ab [2] f2 b1 [2] ec ac [2] ee ad [2] f5 ab [2] e9 ac [2] f5 83 }

  condition:
    any of them
}