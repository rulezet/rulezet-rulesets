rule TTP_XOR_QUAD_CurrentVersionRun_85f5 {
  strings:
    $key_85f5 = { d6 9a [2] f2 94 [2] d9 b8 [2] f7 9a [2] e3 81 [2] ec 9b [2] f2 86 [2] f0 87 [2] eb 81 [2] f7 86 [2] eb a9 }

  condition:
    any of them
}