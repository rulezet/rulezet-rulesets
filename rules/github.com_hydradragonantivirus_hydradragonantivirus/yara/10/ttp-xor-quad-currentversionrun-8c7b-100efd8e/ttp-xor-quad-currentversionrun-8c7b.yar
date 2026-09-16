rule TTP_XOR_QUAD_CurrentVersionRun_8c7b {
  strings:
    $key_8c7b = { df 14 [2] fb 1a [2] d0 36 [2] fe 14 [2] ea 0f [2] e5 15 [2] fb 08 [2] f9 09 [2] e2 0f [2] fe 08 [2] e2 27 }

  condition:
    any of them
}