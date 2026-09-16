rule TTP_XOR_QUAD_CurrentVersionRun_8c3e {
  strings:
    $key_8c3e = { df 51 [2] fb 5f [2] d0 73 [2] fe 51 [2] ea 4a [2] e5 50 [2] fb 4d [2] f9 4c [2] e2 4a [2] fe 4d [2] e2 62 }

  condition:
    any of them
}