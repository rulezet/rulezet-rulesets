rule TTP_XOR_QUAD_CurrentVersionRun_8c8c {
  strings:
    $key_8c8c = { df e3 [2] fb ed [2] d0 c1 [2] fe e3 [2] ea f8 [2] e5 e2 [2] fb ff [2] f9 fe [2] e2 f8 [2] fe ff [2] e2 d0 }

  condition:
    any of them
}