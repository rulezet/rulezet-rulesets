rule TTP_XOR_QUAD_CurrentVersionRun_fc8e {
  strings:
    $key_fc8e = { af e1 [2] 8b ef [2] a0 c3 [2] 8e e1 [2] 9a fa [2] 95 e0 [2] 8b fd [2] 89 fc [2] 92 fa [2] 8e fd [2] 92 d2 }

  condition:
    any of them
}