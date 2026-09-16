rule TTP_XOR_QUAD_CurrentVersionRun_8c04 {
  strings:
    $key_8c04 = { df 6b [2] fb 65 [2] d0 49 [2] fe 6b [2] ea 70 [2] e5 6a [2] fb 77 [2] f9 76 [2] e2 70 [2] fe 77 [2] e2 58 }

  condition:
    any of them
}