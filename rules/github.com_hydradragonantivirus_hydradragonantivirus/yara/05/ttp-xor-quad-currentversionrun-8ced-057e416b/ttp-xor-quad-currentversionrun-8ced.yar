rule TTP_XOR_QUAD_CurrentVersionRun_8ced {
  strings:
    $key_8ced = { df 82 [2] fb 8c [2] d0 a0 [2] fe 82 [2] ea 99 [2] e5 83 [2] fb 9e [2] f9 9f [2] e2 99 [2] fe 9e [2] e2 b1 }

  condition:
    any of them
}