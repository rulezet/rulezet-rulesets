rule TTP_XOR_QUAD_CurrentVersionRun_9ed3 {
  strings:
    $key_9ed3 = { cd bc [2] e9 b2 [2] c2 9e [2] ec bc [2] f8 a7 [2] f7 bd [2] e9 a0 [2] eb a1 [2] f0 a7 [2] ec a0 [2] f0 8f }

  condition:
    any of them
}