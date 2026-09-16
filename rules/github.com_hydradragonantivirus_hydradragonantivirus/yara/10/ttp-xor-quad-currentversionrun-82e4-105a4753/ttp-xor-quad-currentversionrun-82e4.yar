rule TTP_XOR_QUAD_CurrentVersionRun_82e4 {
  strings:
    $key_82e4 = { d1 8b [2] f5 85 [2] de a9 [2] f0 8b [2] e4 90 [2] eb 8a [2] f5 97 [2] f7 96 [2] ec 90 [2] f0 97 [2] ec b8 }

  condition:
    any of them
}