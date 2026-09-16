rule TTP_XOR_QUAD_CurrentVersionRun_844d {
  strings:
    $key_844d = { d7 22 [2] f3 2c [2] d8 00 [2] f6 22 [2] e2 39 [2] ed 23 [2] f3 3e [2] f1 3f [2] ea 39 [2] f6 3e [2] ea 11 }

  condition:
    any of them
}