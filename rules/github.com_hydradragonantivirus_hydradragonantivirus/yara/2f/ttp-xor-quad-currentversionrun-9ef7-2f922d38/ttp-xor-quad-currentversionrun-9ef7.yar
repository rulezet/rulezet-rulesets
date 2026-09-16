rule TTP_XOR_QUAD_CurrentVersionRun_9ef7 {
  strings:
    $key_9ef7 = { cd 98 [2] e9 96 [2] c2 ba [2] ec 98 [2] f8 83 [2] f7 99 [2] e9 84 [2] eb 85 [2] f0 83 [2] ec 84 [2] f0 ab }

  condition:
    any of them
}