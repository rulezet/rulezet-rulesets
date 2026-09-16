rule TTP_XOR_QUAD_CurrentVersionRun_8361 {
  strings:
    $key_8361 = { d0 0e [2] f4 00 [2] df 2c [2] f1 0e [2] e5 15 [2] ea 0f [2] f4 12 [2] f6 13 [2] ed 15 [2] f1 12 [2] ed 3d }

  condition:
    any of them
}