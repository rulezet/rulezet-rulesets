rule TTP_XOR_QUAD_CurrentVersionRun_8c98 {
  strings:
    $key_8c98 = { df f7 [2] fb f9 [2] d0 d5 [2] fe f7 [2] ea ec [2] e5 f6 [2] fb eb [2] f9 ea [2] e2 ec [2] fe eb [2] e2 c4 }

  condition:
    any of them
}