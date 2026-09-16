rule TTP_XOR_QUAD_CurrentVersionRun_20b5 {
  strings:
    $key_20b5 = { 73 da [2] 57 d4 [2] 7c f8 [2] 52 da [2] 46 c1 [2] 49 db [2] 57 c6 [2] 55 c7 [2] 4e c1 [2] 52 c6 [2] 4e e9 }

  condition:
    any of them
}