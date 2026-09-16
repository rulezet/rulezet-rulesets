rule TTP_XOR_QUAD_CurrentVersionRun_8cfb {
  strings:
    $key_8cfb = { df 94 [2] fb 9a [2] d0 b6 [2] fe 94 [2] ea 8f [2] e5 95 [2] fb 88 [2] f9 89 [2] e2 8f [2] fe 88 [2] e2 a7 }

  condition:
    any of them
}