rule TTP_XOR_QUAD_CurrentVersionRun_8478 {
  strings:
    $key_8478 = { d7 17 [2] f3 19 [2] d8 35 [2] f6 17 [2] e2 0c [2] ed 16 [2] f3 0b [2] f1 0a [2] ea 0c [2] f6 0b [2] ea 24 }

  condition:
    any of them
}