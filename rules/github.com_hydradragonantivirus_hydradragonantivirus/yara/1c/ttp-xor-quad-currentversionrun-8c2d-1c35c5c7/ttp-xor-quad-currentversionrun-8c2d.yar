rule TTP_XOR_QUAD_CurrentVersionRun_8c2d {
  strings:
    $key_8c2d = { df 42 [2] fb 4c [2] d0 60 [2] fe 42 [2] ea 59 [2] e5 43 [2] fb 5e [2] f9 5f [2] e2 59 [2] fe 5e [2] e2 71 }

  condition:
    any of them
}