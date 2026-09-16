rule TTP_XOR_QUAD_CurrentVersionRun_6a8e {
  strings:
    $key_6a8e = { 39 e1 [2] 1d ef [2] 36 c3 [2] 18 e1 [2] 0c fa [2] 03 e0 [2] 1d fd [2] 1f fc [2] 04 fa [2] 18 fd [2] 04 d2 }

  condition:
    any of them
}