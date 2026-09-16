rule TTP_XOR_QUAD_CurrentVersionRun_8c1b {
  strings:
    $key_8c1b = { df 74 [2] fb 7a [2] d0 56 [2] fe 74 [2] ea 6f [2] e5 75 [2] fb 68 [2] f9 69 [2] e2 6f [2] fe 68 [2] e2 47 }

  condition:
    any of them
}