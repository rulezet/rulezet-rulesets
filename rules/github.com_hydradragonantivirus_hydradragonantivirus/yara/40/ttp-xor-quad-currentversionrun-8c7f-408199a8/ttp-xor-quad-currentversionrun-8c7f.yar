rule TTP_XOR_QUAD_CurrentVersionRun_8c7f {
  strings:
    $key_8c7f = { df 10 [2] fb 1e [2] d0 32 [2] fe 10 [2] ea 0b [2] e5 11 [2] fb 0c [2] f9 0d [2] e2 0b [2] fe 0c [2] e2 23 }

  condition:
    any of them
}