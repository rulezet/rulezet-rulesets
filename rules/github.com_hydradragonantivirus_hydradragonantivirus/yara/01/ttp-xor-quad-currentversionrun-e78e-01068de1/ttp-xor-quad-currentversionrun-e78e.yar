rule TTP_XOR_QUAD_CurrentVersionRun_e78e {
  strings:
    $key_e78e = { b4 e1 [2] 90 ef [2] bb c3 [2] 95 e1 [2] 81 fa [2] 8e e0 [2] 90 fd [2] 92 fc [2] 89 fa [2] 95 fd [2] 89 d2 }

  condition:
    any of them
}