rule TTP_XOR_QUAD_CurrentVersionRun_628e {
  strings:
    $key_628e = { 31 e1 [2] 15 ef [2] 3e c3 [2] 10 e1 [2] 04 fa [2] 0b e0 [2] 15 fd [2] 17 fc [2] 0c fa [2] 10 fd [2] 0c d2 }

  condition:
    any of them
}