rule TTP_XOR_QUAD_CurrentVersionRun_1c8e {
  strings:
    $key_1c8e = { 4f e1 [2] 6b ef [2] 40 c3 [2] 6e e1 [2] 7a fa [2] 75 e0 [2] 6b fd [2] 69 fc [2] 72 fa [2] 6e fd [2] 72 d2 }

  condition:
    any of them
}