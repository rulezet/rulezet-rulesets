rule TTP_XOR_QUAD_CurrentVersionRun_83ef {
  strings:
    $key_83ef = { d0 80 [2] f4 8e [2] df a2 [2] f1 80 [2] e5 9b [2] ea 81 [2] f4 9c [2] f6 9d [2] ed 9b [2] f1 9c [2] ed b3 }

  condition:
    any of them
}