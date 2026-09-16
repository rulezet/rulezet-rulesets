rule TTP_XOR_QUAD_CurrentVersionRun_148e {
  strings:
    $key_148e = { 47 e1 [2] 63 ef [2] 48 c3 [2] 66 e1 [2] 72 fa [2] 7d e0 [2] 63 fd [2] 61 fc [2] 7a fa [2] 66 fd [2] 7a d2 }

  condition:
    any of them
}