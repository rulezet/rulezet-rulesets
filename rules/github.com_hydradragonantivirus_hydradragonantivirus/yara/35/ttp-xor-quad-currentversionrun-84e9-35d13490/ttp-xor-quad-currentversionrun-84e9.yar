rule TTP_XOR_QUAD_CurrentVersionRun_84e9 {
  strings:
    $key_84e9 = { d7 86 [2] f3 88 [2] d8 a4 [2] f6 86 [2] e2 9d [2] ed 87 [2] f3 9a [2] f1 9b [2] ea 9d [2] f6 9a [2] ea b5 }

  condition:
    any of them
}