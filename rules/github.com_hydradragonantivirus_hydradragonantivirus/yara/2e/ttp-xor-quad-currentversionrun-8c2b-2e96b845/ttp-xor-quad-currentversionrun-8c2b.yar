rule TTP_XOR_QUAD_CurrentVersionRun_8c2b {
  strings:
    $key_8c2b = { df 44 [2] fb 4a [2] d0 66 [2] fe 44 [2] ea 5f [2] e5 45 [2] fb 58 [2] f9 59 [2] e2 5f [2] fe 58 [2] e2 77 }

  condition:
    any of them
}