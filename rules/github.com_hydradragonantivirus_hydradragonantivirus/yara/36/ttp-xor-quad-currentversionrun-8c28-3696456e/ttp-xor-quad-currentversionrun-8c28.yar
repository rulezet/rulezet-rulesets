rule TTP_XOR_QUAD_CurrentVersionRun_8c28 {
  strings:
    $key_8c28 = { df 47 [2] fb 49 [2] d0 65 [2] fe 47 [2] ea 5c [2] e5 46 [2] fb 5b [2] f9 5a [2] e2 5c [2] fe 5b [2] e2 74 }

  condition:
    any of them
}