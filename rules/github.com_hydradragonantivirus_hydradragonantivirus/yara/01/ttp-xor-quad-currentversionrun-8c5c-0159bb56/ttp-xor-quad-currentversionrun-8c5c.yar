rule TTP_XOR_QUAD_CurrentVersionRun_8c5c {
  strings:
    $key_8c5c = { df 33 [2] fb 3d [2] d0 11 [2] fe 33 [2] ea 28 [2] e5 32 [2] fb 2f [2] f9 2e [2] e2 28 [2] fe 2f [2] e2 00 }

  condition:
    any of them
}