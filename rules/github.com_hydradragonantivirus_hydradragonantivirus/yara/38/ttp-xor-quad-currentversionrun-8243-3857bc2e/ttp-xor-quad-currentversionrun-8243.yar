rule TTP_XOR_QUAD_CurrentVersionRun_8243 {
  strings:
    $key_8243 = { d1 2c [2] f5 22 [2] de 0e [2] f0 2c [2] e4 37 [2] eb 2d [2] f5 30 [2] f7 31 [2] ec 37 [2] f0 30 [2] ec 1f }

  condition:
    any of them
}