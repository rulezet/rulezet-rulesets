rule TTP_XOR_QUAD_CurrentVersionRun_82df {
  strings:
    $key_82df = { d1 b0 [2] f5 be [2] de 92 [2] f0 b0 [2] e4 ab [2] eb b1 [2] f5 ac [2] f7 ad [2] ec ab [2] f0 ac [2] ec 83 }

  condition:
    any of them
}