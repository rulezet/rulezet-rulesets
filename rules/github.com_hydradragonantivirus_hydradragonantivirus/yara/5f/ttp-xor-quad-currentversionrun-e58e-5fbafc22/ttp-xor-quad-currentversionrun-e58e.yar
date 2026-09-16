rule TTP_XOR_QUAD_CurrentVersionRun_e58e {
  strings:
    $key_e58e = { b6 e1 [2] 92 ef [2] b9 c3 [2] 97 e1 [2] 83 fa [2] 8c e0 [2] 92 fd [2] 90 fc [2] 8b fa [2] 97 fd [2] 8b d2 }

  condition:
    any of them
}