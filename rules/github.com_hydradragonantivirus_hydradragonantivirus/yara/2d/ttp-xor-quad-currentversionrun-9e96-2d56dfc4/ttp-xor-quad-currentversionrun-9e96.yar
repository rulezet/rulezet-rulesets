rule TTP_XOR_QUAD_CurrentVersionRun_9e96 {
  strings:
    $key_9e96 = { cd f9 [2] e9 f7 [2] c2 db [2] ec f9 [2] f8 e2 [2] f7 f8 [2] e9 e5 [2] eb e4 [2] f0 e2 [2] ec e5 [2] f0 ca }

  condition:
    any of them
}