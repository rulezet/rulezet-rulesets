rule TTP_XOR_QUAD_CurrentVersionRun_8c0b {
  strings:
    $key_8c0b = { df 64 [2] fb 6a [2] d0 46 [2] fe 64 [2] ea 7f [2] e5 65 [2] fb 78 [2] f9 79 [2] e2 7f [2] fe 78 [2] e2 57 }

  condition:
    any of them
}