rule TTP_XOR_QUAD_CurrentVersionRun_8c34 {
  strings:
    $key_8c34 = { df 5b [2] fb 55 [2] d0 79 [2] fe 5b [2] ea 40 [2] e5 5a [2] fb 47 [2] f9 46 [2] e2 40 [2] fe 47 [2] e2 68 }

  condition:
    any of them
}