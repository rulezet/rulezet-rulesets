rule TTP_XOR_QUAD_CurrentVersionRun_8c5a {
  strings:
    $key_8c5a = { df 35 [2] fb 3b [2] d0 17 [2] fe 35 [2] ea 2e [2] e5 34 [2] fb 29 [2] f9 28 [2] e2 2e [2] fe 29 [2] e2 06 }

  condition:
    any of them
}