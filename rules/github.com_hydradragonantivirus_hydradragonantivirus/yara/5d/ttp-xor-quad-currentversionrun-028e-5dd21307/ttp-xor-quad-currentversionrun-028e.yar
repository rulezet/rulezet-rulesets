rule TTP_XOR_QUAD_CurrentVersionRun_028e {
  strings:
    $key_028e = { 51 e1 [2] 75 ef [2] 5e c3 [2] 70 e1 [2] 64 fa [2] 6b e0 [2] 75 fd [2] 77 fc [2] 6c fa [2] 70 fd [2] 6c d2 }

  condition:
    any of them
}