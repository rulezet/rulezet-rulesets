rule TTP_XOR_QUAD_CurrentVersionRun_328e {
  strings:
    $key_328e = { 61 e1 [2] 45 ef [2] 6e c3 [2] 40 e1 [2] 54 fa [2] 5b e0 [2] 45 fd [2] 47 fc [2] 5c fa [2] 40 fd [2] 5c d2 }

  condition:
    any of them
}