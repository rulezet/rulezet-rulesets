rule TTP_XOR_QUAD_CurrentVersionRun_498e {
  strings:
    $key_498e = { 1a e1 [2] 3e ef [2] 15 c3 [2] 3b e1 [2] 2f fa [2] 20 e0 [2] 3e fd [2] 3c fc [2] 27 fa [2] 3b fd [2] 27 d2 }

  condition:
    any of them
}