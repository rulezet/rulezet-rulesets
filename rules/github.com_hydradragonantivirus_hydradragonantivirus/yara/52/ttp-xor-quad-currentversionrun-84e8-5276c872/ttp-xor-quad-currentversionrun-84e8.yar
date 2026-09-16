rule TTP_XOR_QUAD_CurrentVersionRun_84e8 {
  strings:
    $key_84e8 = { d7 87 [2] f3 89 [2] d8 a5 [2] f6 87 [2] e2 9c [2] ed 86 [2] f3 9b [2] f1 9a [2] ea 9c [2] f6 9b [2] ea b4 }

  condition:
    any of them
}