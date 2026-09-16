rule TTP_XOR_QUAD_CurrentVersionRun_6b8e {
  strings:
    $key_6b8e = { 38 e1 [2] 1c ef [2] 37 c3 [2] 19 e1 [2] 0d fa [2] 02 e0 [2] 1c fd [2] 1e fc [2] 05 fa [2] 19 fd [2] 05 d2 }

  condition:
    any of them
}