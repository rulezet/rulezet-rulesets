rule TTP_XOR_QUAD_CurrentVersionRun_8c4c {
  strings:
    $key_8c4c = { df 23 [2] fb 2d [2] d0 01 [2] fe 23 [2] ea 38 [2] e5 22 [2] fb 3f [2] f9 3e [2] e2 38 [2] fe 3f [2] e2 10 }

  condition:
    any of them
}