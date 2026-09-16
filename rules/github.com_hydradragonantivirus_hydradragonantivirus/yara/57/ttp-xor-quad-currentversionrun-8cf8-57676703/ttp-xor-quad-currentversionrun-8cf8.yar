rule TTP_XOR_QUAD_CurrentVersionRun_8cf8 {
  strings:
    $key_8cf8 = { df 97 [2] fb 99 [2] d0 b5 [2] fe 97 [2] ea 8c [2] e5 96 [2] fb 8b [2] f9 8a [2] e2 8c [2] fe 8b [2] e2 a4 }

  condition:
    any of them
}