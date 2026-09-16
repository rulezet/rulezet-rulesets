rule TTP_XOR_QUAD_CurrentVersionRun_8c2f {
  strings:
    $key_8c2f = { df 40 [2] fb 4e [2] d0 62 [2] fe 40 [2] ea 5b [2] e5 41 [2] fb 5c [2] f9 5d [2] e2 5b [2] fe 5c [2] e2 73 }

  condition:
    any of them
}