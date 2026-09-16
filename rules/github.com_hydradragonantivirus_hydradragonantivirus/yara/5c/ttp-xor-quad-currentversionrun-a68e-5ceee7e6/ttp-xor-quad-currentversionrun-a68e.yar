rule TTP_XOR_QUAD_CurrentVersionRun_a68e {
  strings:
    $key_a68e = { f5 e1 [2] d1 ef [2] fa c3 [2] d4 e1 [2] c0 fa [2] cf e0 [2] d1 fd [2] d3 fc [2] c8 fa [2] d4 fd [2] c8 d2 }

  condition:
    any of them
}