rule TTP_XOR_QUAD_CurrentVersionRun_9ef3 {
  strings:
    $key_9ef3 = { cd 9c [2] e9 92 [2] c2 be [2] ec 9c [2] f8 87 [2] f7 9d [2] e9 80 [2] eb 81 [2] f0 87 [2] ec 80 [2] f0 af }

  condition:
    any of them
}