rule TTP_XOR_QUAD_CurrentVersionRun_8261 {
  strings:
    $key_8261 = { d1 0e [2] f5 00 [2] de 2c [2] f0 0e [2] e4 15 [2] eb 0f [2] f5 12 [2] f7 13 [2] ec 15 [2] f0 12 [2] ec 3d }

  condition:
    any of them
}