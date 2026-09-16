rule TTP_XOR_QUAD_CurrentVersionRun_8c4a {
  strings:
    $key_8c4a = { df 25 [2] fb 2b [2] d0 07 [2] fe 25 [2] ea 3e [2] e5 24 [2] fb 39 [2] f9 38 [2] e2 3e [2] fe 39 [2] e2 16 }

  condition:
    any of them
}