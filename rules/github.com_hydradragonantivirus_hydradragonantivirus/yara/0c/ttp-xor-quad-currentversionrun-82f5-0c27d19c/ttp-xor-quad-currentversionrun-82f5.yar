rule TTP_XOR_QUAD_CurrentVersionRun_82f5 {
  strings:
    $key_82f5 = { d1 9a [2] f5 94 [2] de b8 [2] f0 9a [2] e4 81 [2] eb 9b [2] f5 86 [2] f7 87 [2] ec 81 [2] f0 86 [2] ec a9 }

  condition:
    any of them
}