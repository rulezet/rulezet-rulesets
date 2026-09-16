rule TTP_XOR_QUAD_CurrentVersionRun_ec8e {
  strings:
    $key_ec8e = { bf e1 [2] 9b ef [2] b0 c3 [2] 9e e1 [2] 8a fa [2] 85 e0 [2] 9b fd [2] 99 fc [2] 82 fa [2] 9e fd [2] 82 d2 }

  condition:
    any of them
}