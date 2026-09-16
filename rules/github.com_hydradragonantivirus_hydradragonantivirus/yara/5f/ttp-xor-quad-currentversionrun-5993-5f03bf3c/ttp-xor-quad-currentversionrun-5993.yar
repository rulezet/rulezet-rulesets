rule TTP_XOR_QUAD_CurrentVersionRun_5993 {
  strings:
    $key_5993 = { 0a fc [2] 2e f2 [2] 05 de [2] 2b fc [2] 3f e7 [2] 30 fd [2] 2e e0 [2] 2c e1 [2] 37 e7 [2] 2b e0 [2] 37 cf }

  condition:
    any of them
}