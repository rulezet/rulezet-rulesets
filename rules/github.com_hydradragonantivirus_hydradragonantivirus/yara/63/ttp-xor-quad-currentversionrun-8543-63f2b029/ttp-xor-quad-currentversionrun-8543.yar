rule TTP_XOR_QUAD_CurrentVersionRun_8543 {
  strings:
    $key_8543 = { d6 2c [2] f2 22 [2] d9 0e [2] f7 2c [2] e3 37 [2] ec 2d [2] f2 30 [2] f0 31 [2] eb 37 [2] f7 30 [2] eb 1f }

  condition:
    any of them
}