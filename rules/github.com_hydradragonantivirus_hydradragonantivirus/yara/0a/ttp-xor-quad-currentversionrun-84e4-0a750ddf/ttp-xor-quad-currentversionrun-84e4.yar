rule TTP_XOR_QUAD_CurrentVersionRun_84e4 {
  strings:
    $key_84e4 = { d7 8b [2] f3 85 [2] d8 a9 [2] f6 8b [2] e2 90 [2] ed 8a [2] f3 97 [2] f1 96 [2] ea 90 [2] f6 97 [2] ea b8 }

  condition:
    any of them
}