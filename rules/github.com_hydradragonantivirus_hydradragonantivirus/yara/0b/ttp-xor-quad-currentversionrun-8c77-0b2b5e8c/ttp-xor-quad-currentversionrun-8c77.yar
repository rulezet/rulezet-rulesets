rule TTP_XOR_QUAD_CurrentVersionRun_8c77 {
  strings:
    $key_8c77 = { df 18 [2] fb 16 [2] d0 3a [2] fe 18 [2] ea 03 [2] e5 19 [2] fb 04 [2] f9 05 [2] e2 03 [2] fe 04 [2] e2 2b }

  condition:
    any of them
}