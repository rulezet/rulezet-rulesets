rule TTP_XOR_QUAD_CurrentVersionRun_8428 {
  strings:
    $key_8428 = { d7 47 [2] f3 49 [2] d8 65 [2] f6 47 [2] e2 5c [2] ed 46 [2] f3 5b [2] f1 5a [2] ea 5c [2] f6 5b [2] ea 74 }

  condition:
    any of them
}