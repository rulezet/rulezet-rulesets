rule TTP_XOR_QUAD_CurrentVersionRun_8434 {
  strings:
    $key_8434 = { d7 5b [2] f3 55 [2] d8 79 [2] f6 5b [2] e2 40 [2] ed 5a [2] f3 47 [2] f1 46 [2] ea 40 [2] f6 47 [2] ea 68 }

  condition:
    any of them
}