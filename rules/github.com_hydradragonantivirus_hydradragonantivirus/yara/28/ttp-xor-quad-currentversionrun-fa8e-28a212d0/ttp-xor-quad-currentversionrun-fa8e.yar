rule TTP_XOR_QUAD_CurrentVersionRun_fa8e {
  strings:
    $key_fa8e = { a9 e1 [2] 8d ef [2] a6 c3 [2] 88 e1 [2] 9c fa [2] 93 e0 [2] 8d fd [2] 8f fc [2] 94 fa [2] 88 fd [2] 94 d2 }

  condition:
    any of them
}