rule TTP_XOR_QUAD_CurrentVersionRun_8c56 {
  strings:
    $key_8c56 = { df 39 [2] fb 37 [2] d0 1b [2] fe 39 [2] ea 22 [2] e5 38 [2] fb 25 [2] f9 24 [2] e2 22 [2] fe 25 [2] e2 0a }

  condition:
    any of them
}