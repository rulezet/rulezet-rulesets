rule TTP_XOR_QUAD_CurrentVersionRun_8c0e {
  strings:
    $key_8c0e = { df 61 [2] fb 6f [2] d0 43 [2] fe 61 [2] ea 7a [2] e5 60 [2] fb 7d [2] f9 7c [2] e2 7a [2] fe 7d [2] e2 52 }

  condition:
    any of them
}