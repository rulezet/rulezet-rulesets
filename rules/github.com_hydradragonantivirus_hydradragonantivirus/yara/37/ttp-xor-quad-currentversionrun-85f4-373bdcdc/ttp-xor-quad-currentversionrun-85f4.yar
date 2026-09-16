rule TTP_XOR_QUAD_CurrentVersionRun_85f4 {
  strings:
    $key_85f4 = { d6 9b [2] f2 95 [2] d9 b9 [2] f7 9b [2] e3 80 [2] ec 9a [2] f2 87 [2] f0 86 [2] eb 80 [2] f7 87 [2] eb a8 }

  condition:
    any of them
}