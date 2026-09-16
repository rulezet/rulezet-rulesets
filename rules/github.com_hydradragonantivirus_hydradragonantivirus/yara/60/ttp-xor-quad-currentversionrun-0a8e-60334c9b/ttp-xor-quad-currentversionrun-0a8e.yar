rule TTP_XOR_QUAD_CurrentVersionRun_0a8e {
  strings:
    $key_0a8e = { 59 e1 [2] 7d ef [2] 56 c3 [2] 78 e1 [2] 6c fa [2] 63 e0 [2] 7d fd [2] 7f fc [2] 64 fa [2] 78 fd [2] 64 d2 }

  condition:
    any of them
}