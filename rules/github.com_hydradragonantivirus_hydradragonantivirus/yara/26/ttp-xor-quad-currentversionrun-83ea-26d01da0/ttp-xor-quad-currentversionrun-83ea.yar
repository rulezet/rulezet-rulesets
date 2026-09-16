rule TTP_XOR_QUAD_CurrentVersionRun_83ea {
  strings:
    $key_83ea = { d0 85 [2] f4 8b [2] df a7 [2] f1 85 [2] e5 9e [2] ea 84 [2] f4 99 [2] f6 98 [2] ed 9e [2] f1 99 [2] ed b6 }

  condition:
    any of them
}