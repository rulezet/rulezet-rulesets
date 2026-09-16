rule TTP_XOR_QUAD_CurrentVersionRun_9eb5 {
  strings:
    $key_9eb5 = { cd da [2] e9 d4 [2] c2 f8 [2] ec da [2] f8 c1 [2] f7 db [2] e9 c6 [2] eb c7 [2] f0 c1 [2] ec c6 [2] f0 e9 }

  condition:
    any of them
}