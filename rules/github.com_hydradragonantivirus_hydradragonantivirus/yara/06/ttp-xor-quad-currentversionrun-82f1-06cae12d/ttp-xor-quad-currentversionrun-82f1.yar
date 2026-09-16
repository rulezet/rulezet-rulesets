rule TTP_XOR_QUAD_CurrentVersionRun_82f1 {
  strings:
    $key_82f1 = { d1 9e [2] f5 90 [2] de bc [2] f0 9e [2] e4 85 [2] eb 9f [2] f5 82 [2] f7 83 [2] ec 85 [2] f0 82 [2] ec ad }

  condition:
    any of them
}