rule TTP_XOR_QUAD_CurrentVersionRun_8c50 {
  strings:
    $key_8c50 = { df 3f [2] fb 31 [2] d0 1d [2] fe 3f [2] ea 24 [2] e5 3e [2] fb 23 [2] f9 22 [2] e2 24 [2] fe 23 [2] e2 0c }

  condition:
    any of them
}