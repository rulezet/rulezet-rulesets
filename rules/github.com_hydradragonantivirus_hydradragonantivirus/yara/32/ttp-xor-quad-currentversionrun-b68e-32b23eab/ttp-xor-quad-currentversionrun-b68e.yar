rule TTP_XOR_QUAD_CurrentVersionRun_b68e {
  strings:
    $key_b68e = { e5 e1 [2] c1 ef [2] ea c3 [2] c4 e1 [2] d0 fa [2] df e0 [2] c1 fd [2] c3 fc [2] d8 fa [2] c4 fd [2] d8 d2 }

  condition:
    any of them
}