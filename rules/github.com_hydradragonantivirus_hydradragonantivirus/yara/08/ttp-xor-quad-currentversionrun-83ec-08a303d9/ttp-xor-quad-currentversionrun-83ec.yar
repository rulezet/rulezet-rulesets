rule TTP_XOR_QUAD_CurrentVersionRun_83ec {
  strings:
    $key_83ec = { d0 83 [2] f4 8d [2] df a1 [2] f1 83 [2] e5 98 [2] ea 82 [2] f4 9f [2] f6 9e [2] ed 98 [2] f1 9f [2] ed b0 }

  condition:
    any of them
}