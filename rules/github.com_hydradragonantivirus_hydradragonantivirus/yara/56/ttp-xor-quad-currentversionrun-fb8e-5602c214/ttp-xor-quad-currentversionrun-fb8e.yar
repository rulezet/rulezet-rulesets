rule TTP_XOR_QUAD_CurrentVersionRun_fb8e {
  strings:
    $key_fb8e = { a8 e1 [2] 8c ef [2] a7 c3 [2] 89 e1 [2] 9d fa [2] 92 e0 [2] 8c fd [2] 8e fc [2] 95 fa [2] 89 fd [2] 95 d2 }

  condition:
    any of them
}