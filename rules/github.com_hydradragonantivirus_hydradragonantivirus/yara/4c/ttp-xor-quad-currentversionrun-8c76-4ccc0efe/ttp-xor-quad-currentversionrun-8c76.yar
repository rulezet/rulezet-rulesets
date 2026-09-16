rule TTP_XOR_QUAD_CurrentVersionRun_8c76 {
  strings:
    $key_8c76 = { df 19 [2] fb 17 [2] d0 3b [2] fe 19 [2] ea 02 [2] e5 18 [2] fb 05 [2] f9 04 [2] e2 02 [2] fe 05 [2] e2 2a }

  condition:
    any of them
}