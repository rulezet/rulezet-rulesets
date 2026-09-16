rule TTP_XOR_QUAD_CurrentVersionRun_8c07 {
  strings:
    $key_8c07 = { df 68 [2] fb 66 [2] d0 4a [2] fe 68 [2] ea 73 [2] e5 69 [2] fb 74 [2] f9 75 [2] e2 73 [2] fe 74 [2] e2 5b }

  condition:
    any of them
}