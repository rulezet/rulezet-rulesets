rule TTP_XOR_QUAD_CurrentVersionRun_82e9 {
  strings:
    $key_82e9 = { d1 86 [2] f5 88 [2] de a4 [2] f0 86 [2] e4 9d [2] eb 87 [2] f5 9a [2] f7 9b [2] ec 9d [2] f0 9a [2] ec b5 }

  condition:
    any of them
}