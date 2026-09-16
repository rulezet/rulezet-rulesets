rule TTP_XOR_QUAD_CurrentVersionRun_20b4 {
  strings:
    $key_20b4 = { 73 db [2] 57 d5 [2] 7c f9 [2] 52 db [2] 46 c0 [2] 49 da [2] 57 c7 [2] 55 c6 [2] 4e c0 [2] 52 c7 [2] 4e e8 }

  condition:
    any of them
}