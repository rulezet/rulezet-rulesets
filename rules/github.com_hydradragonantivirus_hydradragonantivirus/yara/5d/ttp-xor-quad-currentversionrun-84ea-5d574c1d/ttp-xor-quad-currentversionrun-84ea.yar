rule TTP_XOR_QUAD_CurrentVersionRun_84ea {
  strings:
    $key_84ea = { d7 85 [2] f3 8b [2] d8 a7 [2] f6 85 [2] e2 9e [2] ed 84 [2] f3 99 [2] f1 98 [2] ea 9e [2] f6 99 [2] ea b6 }

  condition:
    any of them
}