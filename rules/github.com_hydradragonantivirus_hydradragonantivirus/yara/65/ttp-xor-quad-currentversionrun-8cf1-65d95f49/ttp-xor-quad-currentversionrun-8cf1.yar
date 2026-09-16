rule TTP_XOR_QUAD_CurrentVersionRun_8cf1 {
  strings:
    $key_8cf1 = { df 9e [2] fb 90 [2] d0 bc [2] fe 9e [2] ea 85 [2] e5 9f [2] fb 82 [2] f9 83 [2] e2 85 [2] fe 82 [2] e2 ad }

  condition:
    any of them
}