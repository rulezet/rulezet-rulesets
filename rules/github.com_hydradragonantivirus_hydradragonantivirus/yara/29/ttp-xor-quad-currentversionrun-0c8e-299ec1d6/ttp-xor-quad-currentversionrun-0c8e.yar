rule TTP_XOR_QUAD_CurrentVersionRun_0c8e {
  strings:
    $key_0c8e = { 5f e1 [2] 7b ef [2] 50 c3 [2] 7e e1 [2] 6a fa [2] 65 e0 [2] 7b fd [2] 79 fc [2] 62 fa [2] 7e fd [2] 62 d2 }

  condition:
    any of them
}