rule TTP_XOR_QUAD_CurrentVersionRun_82c3 {
  strings:
    $key_82c3 = { d1 ac [2] f5 a2 [2] de 8e [2] f0 ac [2] e4 b7 [2] eb ad [2] f5 b0 [2] f7 b1 [2] ec b7 [2] f0 b0 [2] ec 9f }

  condition:
    any of them
}