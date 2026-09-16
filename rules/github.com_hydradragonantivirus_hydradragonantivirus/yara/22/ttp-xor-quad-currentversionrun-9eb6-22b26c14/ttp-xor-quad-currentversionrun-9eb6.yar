rule TTP_XOR_QUAD_CurrentVersionRun_9eb6 {
  strings:
    $key_9eb6 = { cd d9 [2] e9 d7 [2] c2 fb [2] ec d9 [2] f8 c2 [2] f7 d8 [2] e9 c5 [2] eb c4 [2] f0 c2 [2] ec c5 [2] f0 ea }

  condition:
    any of them
}