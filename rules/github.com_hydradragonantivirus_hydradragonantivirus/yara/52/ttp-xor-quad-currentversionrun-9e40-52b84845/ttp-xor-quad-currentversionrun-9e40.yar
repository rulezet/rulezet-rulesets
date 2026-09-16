rule TTP_XOR_QUAD_CurrentVersionRun_9e40 {
  strings:
    $key_9e40 = { cd 2f [2] e9 21 [2] c2 0d [2] ec 2f [2] f8 34 [2] f7 2e [2] e9 33 [2] eb 32 [2] f0 34 [2] ec 33 [2] f0 1c }

  condition:
    any of them
}