rule TTP_XOR_QUAD_CurrentVersionRun_8c58 {
  strings:
    $key_8c58 = { df 37 [2] fb 39 [2] d0 15 [2] fe 37 [2] ea 2c [2] e5 36 [2] fb 2b [2] f9 2a [2] e2 2c [2] fe 2b [2] e2 04 }

  condition:
    any of them
}