rule TTP_XOR_QUAD_CurrentVersionRun_82c2 {
  strings:
    $key_82c2 = { d1 ad [2] f5 a3 [2] de 8f [2] f0 ad [2] e4 b6 [2] eb ac [2] f5 b1 [2] f7 b0 [2] ec b6 [2] f0 b1 [2] ec 9e }

  condition:
    any of them
}