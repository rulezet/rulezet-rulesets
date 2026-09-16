rule TTP_XOR_QUAD_CurrentVersionRun_82ea {
  strings:
    $key_82ea = { d1 85 [2] f5 8b [2] de a7 [2] f0 85 [2] e4 9e [2] eb 84 [2] f5 99 [2] f7 98 [2] ec 9e [2] f0 99 [2] ec b6 }

  condition:
    any of them
}