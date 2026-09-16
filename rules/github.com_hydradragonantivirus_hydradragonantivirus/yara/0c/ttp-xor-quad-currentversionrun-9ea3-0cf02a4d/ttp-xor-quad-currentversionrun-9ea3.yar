rule TTP_XOR_QUAD_CurrentVersionRun_9ea3 {
  strings:
    $key_9ea3 = { cd cc [2] e9 c2 [2] c2 ee [2] ec cc [2] f8 d7 [2] f7 cd [2] e9 d0 [2] eb d1 [2] f0 d7 [2] ec d0 [2] f0 ff }

  condition:
    any of them
}