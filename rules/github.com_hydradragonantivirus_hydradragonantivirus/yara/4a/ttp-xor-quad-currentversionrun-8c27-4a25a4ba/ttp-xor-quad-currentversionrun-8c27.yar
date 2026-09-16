rule TTP_XOR_QUAD_CurrentVersionRun_8c27 {
  strings:
    $key_8c27 = { df 48 [2] fb 46 [2] d0 6a [2] fe 48 [2] ea 53 [2] e5 49 [2] fb 54 [2] f9 55 [2] e2 53 [2] fe 54 [2] e2 7b }

  condition:
    any of them
}