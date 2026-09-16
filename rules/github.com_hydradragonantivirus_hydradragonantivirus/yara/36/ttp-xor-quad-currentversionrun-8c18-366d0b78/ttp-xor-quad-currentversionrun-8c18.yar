rule TTP_XOR_QUAD_CurrentVersionRun_8c18 {
  strings:
    $key_8c18 = { df 77 [2] fb 79 [2] d0 55 [2] fe 77 [2] ea 6c [2] e5 76 [2] fb 6b [2] f9 6a [2] e2 6c [2] fe 6b [2] e2 44 }

  condition:
    any of them
}