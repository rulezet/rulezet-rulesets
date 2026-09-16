rule TTP_XOR_QUAD_CurrentVersionRun_84ef {
  strings:
    $key_84ef = { d7 80 [2] f3 8e [2] d8 a2 [2] f6 80 [2] e2 9b [2] ed 81 [2] f3 9c [2] f1 9d [2] ea 9b [2] f6 9c [2] ea b3 }

  condition:
    any of them
}