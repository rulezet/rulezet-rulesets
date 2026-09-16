rule TTP_XOR_QUAD_CurrentVersionRun_8370 {
  strings:
    $key_8370 = { d0 1f [2] f4 11 [2] df 3d [2] f1 1f [2] e5 04 [2] ea 1e [2] f4 03 [2] f6 02 [2] ed 04 [2] f1 03 [2] ed 2c }

  condition:
    any of them
}