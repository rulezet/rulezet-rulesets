rule TTP_XOR_QUAD_CurrentVersionRun_959c {
  strings:
    $key_959c = { c6 f3 [2] e2 fd [2] c9 d1 [2] e7 f3 [2] f3 e8 [2] fc f2 [2] e2 ef [2] e0 ee [2] fb e8 [2] e7 ef [2] fb c0 }

  condition:
    any of them
}