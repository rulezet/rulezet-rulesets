rule TTP_XOR_QUAD_CurrentVersionRun_7b8e {
  strings:
    $key_7b8e = { 28 e1 [2] 0c ef [2] 27 c3 [2] 09 e1 [2] 1d fa [2] 12 e0 [2] 0c fd [2] 0e fc [2] 15 fa [2] 09 fd [2] 15 d2 }

  condition:
    any of them
}