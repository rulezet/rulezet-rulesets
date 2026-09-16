rule TTP_XOR_QUAD_CurrentVersionRun_9443 {
  strings:
    $key_9443 = { c7 2c [2] e3 22 [2] c8 0e [2] e6 2c [2] f2 37 [2] fd 2d [2] e3 30 [2] e1 31 [2] fa 37 [2] e6 30 [2] fa 1f }

  condition:
    any of them
}