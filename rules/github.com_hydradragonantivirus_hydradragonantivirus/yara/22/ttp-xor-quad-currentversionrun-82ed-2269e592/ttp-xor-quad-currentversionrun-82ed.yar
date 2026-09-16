rule TTP_XOR_QUAD_CurrentVersionRun_82ed {
  strings:
    $key_82ed = { d1 82 [2] f5 8c [2] de a0 [2] f0 82 [2] e4 99 [2] eb 83 [2] f5 9e [2] f7 9f [2] ec 99 [2] f0 9e [2] ec b1 }

  condition:
    any of them
}