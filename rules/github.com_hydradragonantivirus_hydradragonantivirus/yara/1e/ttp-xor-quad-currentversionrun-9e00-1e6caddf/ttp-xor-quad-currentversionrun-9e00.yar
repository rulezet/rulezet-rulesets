rule TTP_XOR_QUAD_CurrentVersionRun_9e00 {
  strings:
    $key_9e00 = { cd 6f [2] e9 61 [2] c2 4d [2] ec 6f [2] f8 74 [2] f7 6e [2] e9 73 [2] eb 72 [2] f0 74 [2] ec 73 [2] f0 5c }

  condition:
    any of them
}