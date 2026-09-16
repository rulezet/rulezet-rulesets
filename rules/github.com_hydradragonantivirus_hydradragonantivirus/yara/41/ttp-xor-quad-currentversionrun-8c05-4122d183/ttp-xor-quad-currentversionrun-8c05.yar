rule TTP_XOR_QUAD_CurrentVersionRun_8c05 {
  strings:
    $key_8c05 = { df 6a [2] fb 64 [2] d0 48 [2] fe 6a [2] ea 71 [2] e5 6b [2] fb 76 [2] f9 77 [2] e2 71 [2] fe 76 [2] e2 59 }

  condition:
    any of them
}