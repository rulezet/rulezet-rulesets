rule TTP_XOR_QUAD_CurrentVersionRun_8c7e {
  strings:
    $key_8c7e = { df 11 [2] fb 1f [2] d0 33 [2] fe 11 [2] ea 0a [2] e5 10 [2] fb 0d [2] f9 0c [2] e2 0a [2] fe 0d [2] e2 22 }

  condition:
    any of them
}