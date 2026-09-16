rule TTP_XOR_QUAD_CurrentVersionRun_8c8f {
  strings:
    $key_8c8f = { df e0 [2] fb ee [2] d0 c2 [2] fe e0 [2] ea fb [2] e5 e1 [2] fb fc [2] f9 fd [2] e2 fb [2] fe fc [2] e2 d3 }

  condition:
    any of them
}