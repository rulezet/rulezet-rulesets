rule TTP_XOR_QUAD_CurrentVersionRun_8cf9 {
  strings:
    $key_8cf9 = { df 96 [2] fb 98 [2] d0 b4 [2] fe 96 [2] ea 8d [2] e5 97 [2] fb 8a [2] f9 8b [2] e2 8d [2] fe 8a [2] e2 a5 }

  condition:
    any of them
}