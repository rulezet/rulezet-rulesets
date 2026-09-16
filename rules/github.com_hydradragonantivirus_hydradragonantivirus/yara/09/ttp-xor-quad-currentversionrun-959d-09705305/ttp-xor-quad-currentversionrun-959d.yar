rule TTP_XOR_QUAD_CurrentVersionRun_959d {
  strings:
    $key_959d = { c6 f2 [2] e2 fc [2] c9 d0 [2] e7 f2 [2] f3 e9 [2] fc f3 [2] e2 ee [2] e0 ef [2] fb e9 [2] e7 ee [2] fb c1 }

  condition:
    any of them
}