rule TTP_XOR_QUAD_CurrentVersionRun_4993 {
  strings:
    $key_4993 = { 1a fc [2] 3e f2 [2] 15 de [2] 3b fc [2] 2f e7 [2] 20 fd [2] 3e e0 [2] 3c e1 [2] 27 e7 [2] 3b e0 [2] 27 cf }

  condition:
    any of them
}