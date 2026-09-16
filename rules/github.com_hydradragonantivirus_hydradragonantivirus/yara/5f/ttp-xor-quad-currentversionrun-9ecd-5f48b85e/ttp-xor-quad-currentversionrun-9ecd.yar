rule TTP_XOR_QUAD_CurrentVersionRun_9ecd {
  strings:
    $key_9ecd = { cd a2 [2] e9 ac [2] c2 80 [2] ec a2 [2] f8 b9 [2] f7 a3 [2] e9 be [2] eb bf [2] f0 b9 [2] ec be [2] f0 91 }

  condition:
    any of them
}