rule TTP_XOR_QUAD_CurrentVersionRun_8c73 {
  strings:
    $key_8c73 = { df 1c [2] fb 12 [2] d0 3e [2] fe 1c [2] ea 07 [2] e5 1d [2] fb 00 [2] f9 01 [2] e2 07 [2] fe 00 [2] e2 2f }

  condition:
    any of them
}