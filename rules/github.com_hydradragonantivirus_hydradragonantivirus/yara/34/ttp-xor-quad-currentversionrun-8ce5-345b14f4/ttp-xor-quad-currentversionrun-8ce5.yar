rule TTP_XOR_QUAD_CurrentVersionRun_8ce5 {
  strings:
    $key_8ce5 = { df 8a [2] fb 84 [2] d0 a8 [2] fe 8a [2] ea 91 [2] e5 8b [2] fb 96 [2] f9 97 [2] e2 91 [2] fe 96 [2] e2 b9 }

  condition:
    any of them
}