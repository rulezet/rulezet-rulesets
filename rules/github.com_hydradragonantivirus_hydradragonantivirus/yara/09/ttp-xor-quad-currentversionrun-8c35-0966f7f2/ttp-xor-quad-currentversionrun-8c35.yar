rule TTP_XOR_QUAD_CurrentVersionRun_8c35 {
  strings:
    $key_8c35 = { df 5a [2] fb 54 [2] d0 78 [2] fe 5a [2] ea 41 [2] e5 5b [2] fb 46 [2] f9 47 [2] e2 41 [2] fe 46 [2] e2 69 }

  condition:
    any of them
}