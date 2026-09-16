rule TTP_XOR_QUAD_CurrentVersionRun_8c66 {
  strings:
    $key_8c66 = { df 09 [2] fb 07 [2] d0 2b [2] fe 09 [2] ea 12 [2] e5 08 [2] fb 15 [2] f9 14 [2] e2 12 [2] fe 15 [2] e2 3a }

  condition:
    any of them
}