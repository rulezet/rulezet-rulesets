rule TTP_XOR_QUAD_CurrentVersionRun_8c8a {
  strings:
    $key_8c8a = { df e5 [2] fb eb [2] d0 c7 [2] fe e5 [2] ea fe [2] e5 e4 [2] fb f9 [2] f9 f8 [2] e2 fe [2] fe f9 [2] e2 d6 }

  condition:
    any of them
}