rule TTP_XOR_QUAD_CurrentVersionRun_8419 {
  strings:
    $key_8419 = { d7 76 [2] f3 78 [2] d8 54 [2] f6 76 [2] e2 6d [2] ed 77 [2] f3 6a [2] f1 6b [2] ea 6d [2] f6 6a [2] ea 45 }

  condition:
    any of them
}