rule TTP_XOR_QUAD_CurrentVersionRun_8c23 {
  strings:
    $key_8c23 = { df 4c [2] fb 42 [2] d0 6e [2] fe 4c [2] ea 57 [2] e5 4d [2] fb 50 [2] f9 51 [2] e2 57 [2] fe 50 [2] e2 7f }

  condition:
    any of them
}