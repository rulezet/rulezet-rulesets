rule TTP_XOR_QUAD_CurrentVersionRun_8cfa {
  strings:
    $key_8cfa = { df 95 [2] fb 9b [2] d0 b7 [2] fe 95 [2] ea 8e [2] e5 94 [2] fb 89 [2] f9 88 [2] e2 8e [2] fe 89 [2] e2 a6 }

  condition:
    any of them
}