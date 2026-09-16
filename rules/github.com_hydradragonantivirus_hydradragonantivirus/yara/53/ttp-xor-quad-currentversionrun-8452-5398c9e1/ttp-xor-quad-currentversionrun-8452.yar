rule TTP_XOR_QUAD_CurrentVersionRun_8452 {
  strings:
    $key_8452 = { d7 3d [2] f3 33 [2] d8 1f [2] f6 3d [2] e2 26 [2] ed 3c [2] f3 21 [2] f1 20 [2] ea 26 [2] f6 21 [2] ea 0e }

  condition:
    any of them
}