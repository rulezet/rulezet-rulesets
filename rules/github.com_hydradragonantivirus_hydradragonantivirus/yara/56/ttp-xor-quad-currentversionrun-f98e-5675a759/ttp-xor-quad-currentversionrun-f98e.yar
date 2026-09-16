rule TTP_XOR_QUAD_CurrentVersionRun_f98e {
  strings:
    $key_f98e = { aa e1 [2] 8e ef [2] a5 c3 [2] 8b e1 [2] 9f fa [2] 90 e0 [2] 8e fd [2] 8c fc [2] 97 fa [2] 8b fd [2] 97 d2 }

  condition:
    any of them
}