rule TTP_XOR_QUAD_CurrentVersionRun_8c4d {
  strings:
    $key_8c4d = { df 22 [2] fb 2c [2] d0 00 [2] fe 22 [2] ea 39 [2] e5 23 [2] fb 3e [2] f9 3f [2] e2 39 [2] fe 3e [2] e2 11 }

  condition:
    any of them
}