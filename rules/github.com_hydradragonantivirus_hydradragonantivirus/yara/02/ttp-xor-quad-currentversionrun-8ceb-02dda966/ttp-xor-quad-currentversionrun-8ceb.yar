rule TTP_XOR_QUAD_CurrentVersionRun_8ceb {
  strings:
    $key_8ceb = { df 84 [2] fb 8a [2] d0 a6 [2] fe 84 [2] ea 9f [2] e5 85 [2] fb 98 [2] f9 99 [2] e2 9f [2] fe 98 [2] e2 b7 }

  condition:
    any of them
}