rule TTP_XOR_QUAD_CurrentVersionRun_9e12 {
  strings:
    $key_9e12 = { cd 7d [2] e9 73 [2] c2 5f [2] ec 7d [2] f8 66 [2] f7 7c [2] e9 61 [2] eb 60 [2] f0 66 [2] ec 61 [2] f0 4e }

  condition:
    any of them
}