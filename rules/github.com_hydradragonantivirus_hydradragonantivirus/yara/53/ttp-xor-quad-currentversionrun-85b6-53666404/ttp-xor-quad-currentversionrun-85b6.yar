rule TTP_XOR_QUAD_CurrentVersionRun_85b6 {
  strings:
    $key_85b6 = { d6 d9 [2] f2 d7 [2] d9 fb [2] f7 d9 [2] e3 c2 [2] ec d8 [2] f2 c5 [2] f0 c4 [2] eb c2 [2] f7 c5 [2] eb ea }

  condition:
    any of them
}