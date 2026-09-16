rule TTP_XOR_QUAD_CurrentVersionRun_844c {
  strings:
    $key_844c = { d7 23 [2] f3 2d [2] d8 01 [2] f6 23 [2] e2 38 [2] ed 22 [2] f3 3f [2] f1 3e [2] ea 38 [2] f6 3f [2] ea 10 }

  condition:
    any of them
}