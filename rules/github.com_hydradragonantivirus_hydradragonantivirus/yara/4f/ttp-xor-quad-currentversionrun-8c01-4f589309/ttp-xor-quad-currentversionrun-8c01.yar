rule TTP_XOR_QUAD_CurrentVersionRun_8c01 {
  strings:
    $key_8c01 = { df 6e [2] fb 60 [2] d0 4c [2] fe 6e [2] ea 75 [2] e5 6f [2] fb 72 [2] f9 73 [2] e2 75 [2] fe 72 [2] e2 5d }

  condition:
    any of them
}