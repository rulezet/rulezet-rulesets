rule TTP_XOR_QUAD_CurrentVersionRun_8c6f {
  strings:
    $key_8c6f = { df 00 [2] fb 0e [2] d0 22 [2] fe 00 [2] ea 1b [2] e5 01 [2] fb 1c [2] f9 1d [2] e2 1b [2] fe 1c [2] e2 33 }

  condition:
    any of them
}