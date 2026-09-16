rule TTP_XOR_QUAD_CurrentVersionRun_258e {
  strings:
    $key_258e = { 76 e1 [2] 52 ef [2] 79 c3 [2] 57 e1 [2] 43 fa [2] 4c e0 [2] 52 fd [2] 50 fc [2] 4b fa [2] 57 fd [2] 4b d2 }

  condition:
    any of them
}