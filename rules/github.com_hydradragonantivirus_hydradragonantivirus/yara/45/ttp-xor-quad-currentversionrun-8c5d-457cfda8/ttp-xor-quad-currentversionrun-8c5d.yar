rule TTP_XOR_QUAD_CurrentVersionRun_8c5d {
  strings:
    $key_8c5d = { df 32 [2] fb 3c [2] d0 10 [2] fe 32 [2] ea 29 [2] e5 33 [2] fb 2e [2] f9 2f [2] e2 29 [2] fe 2e [2] e2 01 }

  condition:
    any of them
}