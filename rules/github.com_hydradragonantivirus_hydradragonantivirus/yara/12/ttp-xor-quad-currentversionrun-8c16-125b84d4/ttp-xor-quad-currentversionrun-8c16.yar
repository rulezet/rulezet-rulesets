rule TTP_XOR_QUAD_CurrentVersionRun_8c16 {
  strings:
    $key_8c16 = { df 79 [2] fb 77 [2] d0 5b [2] fe 79 [2] ea 62 [2] e5 78 [2] fb 65 [2] f9 64 [2] e2 62 [2] fe 65 [2] e2 4a }

  condition:
    any of them
}