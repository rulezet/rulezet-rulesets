rule TTP_XOR_QUAD_CurrentVersionRun_5c8e {
  strings:
    $key_5c8e = { 0f e1 [2] 2b ef [2] 00 c3 [2] 2e e1 [2] 3a fa [2] 35 e0 [2] 2b fd [2] 29 fc [2] 32 fa [2] 2e fd [2] 32 d2 }

  condition:
    any of them
}