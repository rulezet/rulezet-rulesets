rule TTP_XOR_QUAD_CurrentVersionRun_8c14 {
  strings:
    $key_8c14 = { df 7b [2] fb 75 [2] d0 59 [2] fe 7b [2] ea 60 [2] e5 7a [2] fb 67 [2] f9 66 [2] e2 60 [2] fe 67 [2] e2 48 }

  condition:
    any of them
}