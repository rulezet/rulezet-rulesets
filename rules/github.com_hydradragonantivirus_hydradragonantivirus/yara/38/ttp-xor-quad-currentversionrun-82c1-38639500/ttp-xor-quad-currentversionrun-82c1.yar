rule TTP_XOR_QUAD_CurrentVersionRun_82c1 {
  strings:
    $key_82c1 = { d1 ae [2] f5 a0 [2] de 8c [2] f0 ae [2] e4 b5 [2] eb af [2] f5 b2 [2] f7 b3 [2] ec b5 [2] f0 b2 [2] ec 9d }

  condition:
    any of them
}