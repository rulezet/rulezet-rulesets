rule TTP_XOR_QUAD_CurrentVersionRun_8e43 {
  strings:
    $key_8e43 = { dd 2c [2] f9 22 [2] d2 0e [2] fc 2c [2] e8 37 [2] e7 2d [2] f9 30 [2] fb 31 [2] e0 37 [2] fc 30 [2] e0 1f }

  condition:
    any of them
}