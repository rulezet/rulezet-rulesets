rule TTP_XOR_QUAD_CurrentVersionRun_8405 {
  strings:
    $key_8405 = { d7 6a [2] f3 64 [2] d8 48 [2] f6 6a [2] e2 71 [2] ed 6b [2] f3 76 [2] f1 77 [2] ea 71 [2] f6 76 [2] ea 59 }

  condition:
    any of them
}