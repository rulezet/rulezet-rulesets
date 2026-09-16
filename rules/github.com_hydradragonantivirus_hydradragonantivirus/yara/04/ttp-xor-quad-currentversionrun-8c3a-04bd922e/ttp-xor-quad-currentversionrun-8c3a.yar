rule TTP_XOR_QUAD_CurrentVersionRun_8c3a {
  strings:
    $key_8c3a = { df 55 [2] fb 5b [2] d0 77 [2] fe 55 [2] ea 4e [2] e5 54 [2] fb 49 [2] f9 48 [2] e2 4e [2] fe 49 [2] e2 66 }

  condition:
    any of them
}