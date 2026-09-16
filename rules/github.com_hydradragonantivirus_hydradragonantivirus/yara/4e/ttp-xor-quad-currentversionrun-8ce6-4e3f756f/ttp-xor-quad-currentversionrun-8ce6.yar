rule TTP_XOR_QUAD_CurrentVersionRun_8ce6 {
  strings:
    $key_8ce6 = { df 89 [2] fb 87 [2] d0 ab [2] fe 89 [2] ea 92 [2] e5 88 [2] fb 95 [2] f9 94 [2] e2 92 [2] fe 95 [2] e2 ba }

  condition:
    any of them
}