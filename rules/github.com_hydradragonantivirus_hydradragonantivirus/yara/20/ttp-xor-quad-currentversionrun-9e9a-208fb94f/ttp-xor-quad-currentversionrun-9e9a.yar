rule TTP_XOR_QUAD_CurrentVersionRun_9e9a {
  strings:
    $key_9e9a = { cd f5 [2] e9 fb [2] c2 d7 [2] ec f5 [2] f8 ee [2] f7 f4 [2] e9 e9 [2] eb e8 [2] f0 ee [2] ec e9 [2] f0 c6 }

  condition:
    any of them
}