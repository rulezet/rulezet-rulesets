rule TTP_XOR_QUAD_CurrentVersionRun_6993 {
  strings:
    $key_6993 = { 3a fc [2] 1e f2 [2] 35 de [2] 1b fc [2] 0f e7 [2] 00 fd [2] 1e e0 [2] 1c e1 [2] 07 e7 [2] 1b e0 [2] 07 cf }

  condition:
    any of them
}