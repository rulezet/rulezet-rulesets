rule TTP_XOR_QUAD_CurrentVersionRun_598e {
  strings:
    $key_598e = { 0a e1 [2] 2e ef [2] 05 c3 [2] 2b e1 [2] 3f fa [2] 30 e0 [2] 2e fd [2] 2c fc [2] 37 fa [2] 2b fd [2] 37 d2 }

  condition:
    any of them
}