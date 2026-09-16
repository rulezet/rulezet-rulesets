rule TTP_XOR_QUAD_CurrentVersionRun_8c46 {
  strings:
    $key_8c46 = { df 29 [2] fb 27 [2] d0 0b [2] fe 29 [2] ea 32 [2] e5 28 [2] fb 35 [2] f9 34 [2] e2 32 [2] fe 35 [2] e2 1a }

  condition:
    any of them
}