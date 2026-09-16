rule TTP_XOR_QUAD_CurrentVersionRun_83ed {
  strings:
    $key_83ed = { d0 82 [2] f4 8c [2] df a0 [2] f1 82 [2] e5 99 [2] ea 83 [2] f4 9e [2] f6 9f [2] ed 99 [2] f1 9e [2] ed b1 }

  condition:
    any of them
}