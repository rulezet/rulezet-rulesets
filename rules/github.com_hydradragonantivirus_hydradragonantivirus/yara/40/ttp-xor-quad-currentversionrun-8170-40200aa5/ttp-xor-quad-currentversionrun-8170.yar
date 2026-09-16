rule TTP_XOR_QUAD_CurrentVersionRun_8170 {
  strings:
    $key_8170 = { d2 1f [2] f6 11 [2] dd 3d [2] f3 1f [2] e7 04 [2] e8 1e [2] f6 03 [2] f4 02 [2] ef 04 [2] f3 03 [2] ef 2c }

  condition:
    any of them
}