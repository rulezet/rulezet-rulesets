rule TTP_XOR_QUAD_CurrentVersionRun_f28e {
  strings:
    $key_f28e = { a1 e1 [2] 85 ef [2] ae c3 [2] 80 e1 [2] 94 fa [2] 9b e0 [2] 85 fd [2] 87 fc [2] 9c fa [2] 80 fd [2] 9c d2 }

  condition:
    any of them
}