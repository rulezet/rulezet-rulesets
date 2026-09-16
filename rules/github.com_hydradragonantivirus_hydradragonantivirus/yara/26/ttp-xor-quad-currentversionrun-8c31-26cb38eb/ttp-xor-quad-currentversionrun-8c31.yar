rule TTP_XOR_QUAD_CurrentVersionRun_8c31 {
  strings:
    $key_8c31 = { df 5e [2] fb 50 [2] d0 7c [2] fe 5e [2] ea 45 [2] e5 5f [2] fb 42 [2] f9 43 [2] e2 45 [2] fe 42 [2] e2 6d }

  condition:
    any of them
}