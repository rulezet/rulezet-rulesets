rule TTP_XOR_QUAD_CurrentVersionRun_8c12 {
  strings:
    $key_8c12 = { df 7d [2] fb 73 [2] d0 5f [2] fe 7d [2] ea 66 [2] e5 7c [2] fb 61 [2] f9 60 [2] e2 66 [2] fe 61 [2] e2 4e }

  condition:
    any of them
}