rule TTP_XOR_QUAD_CurrentVersionRun_9ec2 {
  strings:
    $key_9ec2 = { cd ad [2] e9 a3 [2] c2 8f [2] ec ad [2] f8 b6 [2] f7 ac [2] e9 b1 [2] eb b0 [2] f0 b6 [2] ec b1 [2] f0 9e }

  condition:
    any of them
}