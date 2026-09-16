rule TTP_XOR_QUAD_CurrentVersionRun_8c03 {
  strings:
    $key_8c03 = { df 6c [2] fb 62 [2] d0 4e [2] fe 6c [2] ea 77 [2] e5 6d [2] fb 70 [2] f9 71 [2] e2 77 [2] fe 70 [2] e2 5f }

  condition:
    any of them
}