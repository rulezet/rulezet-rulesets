rule TTP_XOR_QUAD_CurrentVersionRun_3993 {
  strings:
    $key_3993 = { 6a fc [2] 4e f2 [2] 65 de [2] 4b fc [2] 5f e7 [2] 50 fd [2] 4e e0 [2] 4c e1 [2] 57 e7 [2] 4b e0 [2] 57 cf }

  condition:
    any of them
}