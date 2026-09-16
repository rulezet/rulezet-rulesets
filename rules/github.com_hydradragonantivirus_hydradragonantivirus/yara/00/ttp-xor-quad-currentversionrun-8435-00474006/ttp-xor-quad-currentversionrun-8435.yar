rule TTP_XOR_QUAD_CurrentVersionRun_8435 {
  strings:
    $key_8435 = { d7 5a [2] f3 54 [2] d8 78 [2] f6 5a [2] e2 41 [2] ed 5b [2] f3 46 [2] f1 47 [2] ea 41 [2] f6 46 [2] ea 69 }

  condition:
    any of them
}