rule TTP_XOR_QUAD_CurrentVersionRun_8c61 {
  strings:
    $key_8c61 = { df 0e [2] fb 00 [2] d0 2c [2] fe 0e [2] ea 15 [2] e5 0f [2] fb 12 [2] f9 13 [2] e2 15 [2] fe 12 [2] e2 3d }

  condition:
    any of them
}