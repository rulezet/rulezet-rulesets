rule TTP_XOR_QUAD_CurrentVersionRun_9ba7 {
  strings:
    $key_9ba7 = { c8 c8 [2] ec c6 [2] c7 ea [2] e9 c8 [2] fd d3 [2] f2 c9 [2] ec d4 [2] ee d5 [2] f5 d3 [2] e9 d4 [2] f5 fb }

  condition:
    any of them
}