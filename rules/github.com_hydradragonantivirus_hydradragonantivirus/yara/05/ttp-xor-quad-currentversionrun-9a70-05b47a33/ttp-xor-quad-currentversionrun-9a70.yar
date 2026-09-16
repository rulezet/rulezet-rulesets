rule TTP_XOR_QUAD_CurrentVersionRun_9a70 {
  strings:
    $key_9a70 = { c9 1f [2] ed 11 [2] c6 3d [2] e8 1f [2] fc 04 [2] f3 1e [2] ed 03 [2] ef 02 [2] f4 04 [2] e8 03 [2] f4 2c }

  condition:
    any of them
}