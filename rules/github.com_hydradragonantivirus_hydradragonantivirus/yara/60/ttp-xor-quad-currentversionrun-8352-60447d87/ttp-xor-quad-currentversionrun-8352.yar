rule TTP_XOR_QUAD_CurrentVersionRun_8352 {
  strings:
    $key_8352 = { d0 3d [2] f4 33 [2] df 1f [2] f1 3d [2] e5 26 [2] ea 3c [2] f4 21 [2] f6 20 [2] ed 26 [2] f1 21 [2] ed 0e }

  condition:
    any of them
}