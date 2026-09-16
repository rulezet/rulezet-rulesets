rule TTP_XOR_QUAD_CurrentVersionRun_10b5 {
  strings:
    $key_10b5 = { 43 da [2] 67 d4 [2] 4c f8 [2] 62 da [2] 76 c1 [2] 79 db [2] 67 c6 [2] 65 c7 [2] 7e c1 [2] 62 c6 [2] 7e e9 }

  condition:
    any of them
}