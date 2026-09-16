rule TTP_XOR_QUAD_CurrentVersionRun_8c41 {
  strings:
    $key_8c41 = { df 2e [2] fb 20 [2] d0 0c [2] fe 2e [2] ea 35 [2] e5 2f [2] fb 32 [2] f9 33 [2] e2 35 [2] fe 32 [2] e2 1d }

  condition:
    any of them
}