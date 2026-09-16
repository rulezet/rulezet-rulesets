rule TTP_XOR_QUAD_CurrentVersionRun_8cf4 {
  strings:
    $key_8cf4 = { df 9b [2] fb 95 [2] d0 b9 [2] fe 9b [2] ea 80 [2] e5 9a [2] fb 87 [2] f9 86 [2] e2 80 [2] fe 87 [2] e2 a8 }

  condition:
    any of them
}