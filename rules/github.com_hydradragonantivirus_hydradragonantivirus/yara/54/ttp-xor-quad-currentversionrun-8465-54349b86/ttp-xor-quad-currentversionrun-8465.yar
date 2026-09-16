rule TTP_XOR_QUAD_CurrentVersionRun_8465 {
  strings:
    $key_8465 = { d7 0a [2] f3 04 [2] d8 28 [2] f6 0a [2] e2 11 [2] ed 0b [2] f3 16 [2] f1 17 [2] ea 11 [2] f6 16 [2] ea 39 }

  condition:
    any of them
}