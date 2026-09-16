rule TTP_XOR_QUAD_CurrentVersionRun_84fa {
  strings:
    $key_84fa = { d7 95 [2] f3 9b [2] d8 b7 [2] f6 95 [2] e2 8e [2] ed 94 [2] f3 89 [2] f1 88 [2] ea 8e [2] f6 89 [2] ea a6 }

  condition:
    any of them
}