rule TTP_XOR_QUAD_CurrentVersionRun_8cfc {
  strings:
    $key_8cfc = { df 93 [2] fb 9d [2] d0 b1 [2] fe 93 [2] ea 88 [2] e5 92 [2] fb 8f [2] f9 8e [2] e2 88 [2] fe 8f [2] e2 a0 }

  condition:
    any of them
}