rule TTP_XOR_QUAD_CurrentVersionRun_8c6b {
  strings:
    $key_8c6b = { df 04 [2] fb 0a [2] d0 26 [2] fe 04 [2] ea 1f [2] e5 05 [2] fb 18 [2] f9 19 [2] e2 1f [2] fe 18 [2] e2 37 }

  condition:
    any of them
}