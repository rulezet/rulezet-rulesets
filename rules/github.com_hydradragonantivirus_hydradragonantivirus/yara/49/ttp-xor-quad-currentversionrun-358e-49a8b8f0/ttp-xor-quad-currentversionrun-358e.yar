rule TTP_XOR_QUAD_CurrentVersionRun_358e {
  strings:
    $key_358e = { 66 e1 [2] 42 ef [2] 69 c3 [2] 47 e1 [2] 53 fa [2] 5c e0 [2] 42 fd [2] 40 fc [2] 5b fa [2] 47 fd [2] 5b d2 }

  condition:
    any of them
}