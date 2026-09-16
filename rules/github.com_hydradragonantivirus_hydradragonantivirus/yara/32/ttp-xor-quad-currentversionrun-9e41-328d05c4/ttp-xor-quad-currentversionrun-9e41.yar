rule TTP_XOR_QUAD_CurrentVersionRun_9e41 {
  strings:
    $key_9e41 = { cd 2e [2] e9 20 [2] c2 0c [2] ec 2e [2] f8 35 [2] f7 2f [2] e9 32 [2] eb 33 [2] f0 35 [2] ec 32 [2] f0 1d }

  condition:
    any of them
}