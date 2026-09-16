rule TTP_XOR_QUAD_CurrentVersionRun_9ea9 {
  strings:
    $key_9ea9 = { cd c6 [2] e9 c8 [2] c2 e4 [2] ec c6 [2] f8 dd [2] f7 c7 [2] e9 da [2] eb db [2] f0 dd [2] ec da [2] f0 f5 }

  condition:
    any of them
}