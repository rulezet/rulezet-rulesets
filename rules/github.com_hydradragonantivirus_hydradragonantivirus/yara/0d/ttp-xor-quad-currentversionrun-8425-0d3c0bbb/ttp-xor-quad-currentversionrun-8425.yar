rule TTP_XOR_QUAD_CurrentVersionRun_8425 {
  strings:
    $key_8425 = { d7 4a [2] f3 44 [2] d8 68 [2] f6 4a [2] e2 51 [2] ed 4b [2] f3 56 [2] f1 57 [2] ea 51 [2] f6 56 [2] ea 79 }

  condition:
    any of them
}