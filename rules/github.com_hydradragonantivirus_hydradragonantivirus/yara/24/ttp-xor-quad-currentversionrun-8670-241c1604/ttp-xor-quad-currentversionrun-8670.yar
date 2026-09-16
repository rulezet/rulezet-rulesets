rule TTP_XOR_QUAD_CurrentVersionRun_8670 {
  strings:
    $key_8670 = { d5 1f [2] f1 11 [2] da 3d [2] f4 1f [2] e0 04 [2] ef 1e [2] f1 03 [2] f3 02 [2] e8 04 [2] f4 03 [2] e8 2c }

  condition:
    any of them
}