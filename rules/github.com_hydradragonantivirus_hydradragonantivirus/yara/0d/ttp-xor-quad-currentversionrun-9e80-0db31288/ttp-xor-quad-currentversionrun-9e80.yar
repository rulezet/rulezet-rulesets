rule TTP_XOR_QUAD_CurrentVersionRun_9e80 {
  strings:
    $key_9e80 = { cd ef [2] e9 e1 [2] c2 cd [2] ec ef [2] f8 f4 [2] f7 ee [2] e9 f3 [2] eb f2 [2] f0 f4 [2] ec f3 [2] f0 dc }

  condition:
    any of them
}