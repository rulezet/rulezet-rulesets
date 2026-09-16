rule TTP_XOR_QUAD_CurrentVersionRun_85d6 {
  strings:
    $key_85d6 = { d6 b9 [2] f2 b7 [2] d9 9b [2] f7 b9 [2] e3 a2 [2] ec b8 [2] f2 a5 [2] f0 a4 [2] eb a2 [2] f7 a5 [2] eb 8a }

  condition:
    any of them
}