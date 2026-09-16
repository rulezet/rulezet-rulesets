rule TTP_XOR_QUAD_CurrentVersionRun_8c1c {
  strings:
    $key_8c1c = { df 73 [2] fb 7d [2] d0 51 [2] fe 73 [2] ea 68 [2] e5 72 [2] fb 6f [2] f9 6e [2] e2 68 [2] fe 6f [2] e2 40 }

  condition:
    any of them
}