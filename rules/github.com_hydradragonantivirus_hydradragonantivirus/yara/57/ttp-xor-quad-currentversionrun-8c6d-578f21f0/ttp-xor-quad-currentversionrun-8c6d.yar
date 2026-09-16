rule TTP_XOR_QUAD_CurrentVersionRun_8c6d {
  strings:
    $key_8c6d = { df 02 [2] fb 0c [2] d0 20 [2] fe 02 [2] ea 19 [2] e5 03 [2] fb 1e [2] f9 1f [2] e2 19 [2] fe 1e [2] e2 31 }

  condition:
    any of them
}