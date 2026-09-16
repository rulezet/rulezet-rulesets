rule TTP_XOR_QUAD_CurrentVersionRun_1a8e {
  strings:
    $key_1a8e = { 49 e1 [2] 6d ef [2] 46 c3 [2] 68 e1 [2] 7c fa [2] 73 e0 [2] 6d fd [2] 6f fc [2] 74 fa [2] 68 fd [2] 74 d2 }

  condition:
    any of them
}