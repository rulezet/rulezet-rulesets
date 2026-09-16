rule TTP_XOR_QUAD_CurrentVersionRun_8ce7 {
  strings:
    $key_8ce7 = { df 88 [2] fb 86 [2] d0 aa [2] fe 88 [2] ea 93 [2] e5 89 [2] fb 94 [2] f9 95 [2] e2 93 [2] fe 94 [2] e2 bb }

  condition:
    any of them
}