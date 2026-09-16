rule TTP_XOR_QUAD_CurrentVersionRun_7c8e {
  strings:
    $key_7c8e = { 2f e1 [2] 0b ef [2] 20 c3 [2] 0e e1 [2] 1a fa [2] 15 e0 [2] 0b fd [2] 09 fc [2] 12 fa [2] 0e fd [2] 12 d2 }

  condition:
    any of them
}