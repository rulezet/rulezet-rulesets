rule TTP_XOR_QUAD_CurrentVersionRun_8439 {
  strings:
    $key_8439 = { d7 56 [2] f3 58 [2] d8 74 [2] f6 56 [2] e2 4d [2] ed 57 [2] f3 4a [2] f1 4b [2] ea 4d [2] f6 4a [2] ea 65 }

  condition:
    any of them
}