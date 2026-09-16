rule TTP_XOR_QUAD_CurrentVersionRun_8c8b {
  strings:
    $key_8c8b = { df e4 [2] fb ea [2] d0 c6 [2] fe e4 [2] ea ff [2] e5 e5 [2] fb f8 [2] f9 f9 [2] e2 ff [2] fe f8 [2] e2 d7 }

  condition:
    any of them
}