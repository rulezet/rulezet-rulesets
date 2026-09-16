rule TTP_XOR_QUAD_CurrentVersionRun_82f8 {
  strings:
    $key_82f8 = { d1 97 [2] f5 99 [2] de b5 [2] f0 97 [2] e4 8c [2] eb 96 [2] f5 8b [2] f7 8a [2] ec 8c [2] f0 8b [2] ec a4 }

  condition:
    any of them
}