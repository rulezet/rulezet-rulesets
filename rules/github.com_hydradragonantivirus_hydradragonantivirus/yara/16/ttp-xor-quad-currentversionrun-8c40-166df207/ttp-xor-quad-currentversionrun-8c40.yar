rule TTP_XOR_QUAD_CurrentVersionRun_8c40 {
  strings:
    $key_8c40 = { df 2f [2] fb 21 [2] d0 0d [2] fe 2f [2] ea 34 [2] e5 2e [2] fb 33 [2] f9 32 [2] e2 34 [2] fe 33 [2] e2 1c }

  condition:
    any of them
}