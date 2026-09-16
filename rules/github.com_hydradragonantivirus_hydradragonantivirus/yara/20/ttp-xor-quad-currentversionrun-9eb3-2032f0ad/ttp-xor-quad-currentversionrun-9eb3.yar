rule TTP_XOR_QUAD_CurrentVersionRun_9eb3 {
  strings:
    $key_9eb3 = { cd dc [2] e9 d2 [2] c2 fe [2] ec dc [2] f8 c7 [2] f7 dd [2] e9 c0 [2] eb c1 [2] f0 c7 [2] ec c0 [2] f0 ef }

  condition:
    any of them
}