rule TTP_XOR_QUAD_CurrentVersionRun_82c7 {
  strings:
    $key_82c7 = { d1 a8 [2] f5 a6 [2] de 8a [2] f0 a8 [2] e4 b3 [2] eb a9 [2] f5 b4 [2] f7 b5 [2] ec b3 [2] f0 b4 [2] ec 9b }

  condition:
    any of them
}