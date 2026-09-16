rule TTP_XOR_QUAD_CurrentVersionRun_8c9d {
  strings:
    $key_8c9d = { df f2 [2] fb fc [2] d0 d0 [2] fe f2 [2] ea e9 [2] e5 f3 [2] fb ee [2] f9 ef [2] e2 e9 [2] fe ee [2] e2 c1 }

  condition:
    any of them
}