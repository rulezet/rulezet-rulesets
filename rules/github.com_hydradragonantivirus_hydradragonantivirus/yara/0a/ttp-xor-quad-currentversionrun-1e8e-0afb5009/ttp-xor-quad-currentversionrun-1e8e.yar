rule TTP_XOR_QUAD_CurrentVersionRun_1e8e {
  strings:
    $key_1e8e = { 4d e1 [2] 69 ef [2] 42 c3 [2] 6c e1 [2] 78 fa [2] 77 e0 [2] 69 fd [2] 6b fc [2] 70 fa [2] 6c fd [2] 70 d2 }

  condition:
    any of them
}