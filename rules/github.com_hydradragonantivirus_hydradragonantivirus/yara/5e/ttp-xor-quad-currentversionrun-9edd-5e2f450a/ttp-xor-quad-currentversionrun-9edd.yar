rule TTP_XOR_QUAD_CurrentVersionRun_9edd {
  strings:
    $key_9edd = { cd b2 [2] e9 bc [2] c2 90 [2] ec b2 [2] f8 a9 [2] f7 b3 [2] e9 ae [2] eb af [2] f0 a9 [2] ec ae [2] f0 81 }

  condition:
    any of them
}