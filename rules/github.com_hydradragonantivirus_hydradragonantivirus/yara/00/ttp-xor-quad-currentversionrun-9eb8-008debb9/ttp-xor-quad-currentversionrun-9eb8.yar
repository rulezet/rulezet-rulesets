rule TTP_XOR_QUAD_CurrentVersionRun_9eb8 {
  strings:
    $key_9eb8 = { cd d7 [2] e9 d9 [2] c2 f5 [2] ec d7 [2] f8 cc [2] f7 d6 [2] e9 cb [2] eb ca [2] f0 cc [2] ec cb [2] f0 e4 }

  condition:
    any of them
}