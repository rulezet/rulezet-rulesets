rule TTP_XOR_QUAD_CurrentVersionRun_8437 {
  strings:
    $key_8437 = { d7 58 [2] f3 56 [2] d8 7a [2] f6 58 [2] e2 43 [2] ed 59 [2] f3 44 [2] f1 45 [2] ea 43 [2] f6 44 [2] ea 6b }

  condition:
    any of them
}