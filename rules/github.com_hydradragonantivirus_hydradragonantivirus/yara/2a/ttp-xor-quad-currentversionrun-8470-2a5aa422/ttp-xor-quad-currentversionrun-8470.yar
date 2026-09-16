rule TTP_XOR_QUAD_CurrentVersionRun_8470 {
  strings:
    $key_8470 = { d7 1f [2] f3 11 [2] d8 3d [2] f6 1f [2] e2 04 [2] ed 1e [2] f3 03 [2] f1 02 [2] ea 04 [2] f6 03 [2] ea 2c }

  condition:
    any of them
}