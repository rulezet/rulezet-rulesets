rule TTP_XOR_QUAD_CurrentVersionRun_8c48 {
  strings:
    $key_8c48 = { df 27 [2] fb 29 [2] d0 05 [2] fe 27 [2] ea 3c [2] e5 26 [2] fb 3b [2] f9 3a [2] e2 3c [2] fe 3b [2] e2 14 }

  condition:
    any of them
}