rule TTP_XOR_QUAD_CurrentVersionRun_9ec1 {
  strings:
    $key_9ec1 = { cd ae [2] e9 a0 [2] c2 8c [2] ec ae [2] f8 b5 [2] f7 af [2] e9 b2 [2] eb b3 [2] f0 b5 [2] ec b2 [2] f0 9d }

  condition:
    any of them
}