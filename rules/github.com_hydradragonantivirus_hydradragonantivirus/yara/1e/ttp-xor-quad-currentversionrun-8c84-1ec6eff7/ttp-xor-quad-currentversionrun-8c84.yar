rule TTP_XOR_QUAD_CurrentVersionRun_8c84 {
  strings:
    $key_8c84 = { df eb [2] fb e5 [2] d0 c9 [2] fe eb [2] ea f0 [2] e5 ea [2] fb f7 [2] f9 f6 [2] e2 f0 [2] fe f7 [2] e2 d8 }

  condition:
    any of them
}