rule TTP_XOR_QUAD_CurrentVersionRun_9edc {
  strings:
    $key_9edc = { cd b3 [2] e9 bd [2] c2 91 [2] ec b3 [2] f8 a8 [2] f7 b2 [2] e9 af [2] eb ae [2] f0 a8 [2] ec af [2] f0 80 }

  condition:
    any of them
}