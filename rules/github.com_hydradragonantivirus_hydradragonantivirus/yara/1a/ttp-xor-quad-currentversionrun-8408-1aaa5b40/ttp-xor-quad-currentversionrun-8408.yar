rule TTP_XOR_QUAD_CurrentVersionRun_8408 {
  strings:
    $key_8408 = { d7 67 [2] f3 69 [2] d8 45 [2] f6 67 [2] e2 7c [2] ed 66 [2] f3 7b [2] f1 7a [2] ea 7c [2] f6 7b [2] ea 54 }

  condition:
    any of them
}