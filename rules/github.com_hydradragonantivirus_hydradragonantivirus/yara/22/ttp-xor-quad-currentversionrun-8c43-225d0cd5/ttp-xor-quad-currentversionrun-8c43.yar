rule TTP_XOR_QUAD_CurrentVersionRun_8c43 {
  strings:
    $key_8c43 = { df 2c [2] fb 22 [2] d0 0e [2] fe 2c [2] ea 37 [2] e5 2d [2] fb 30 [2] f9 31 [2] e2 37 [2] fe 30 [2] e2 1f }

  condition:
    any of them
}