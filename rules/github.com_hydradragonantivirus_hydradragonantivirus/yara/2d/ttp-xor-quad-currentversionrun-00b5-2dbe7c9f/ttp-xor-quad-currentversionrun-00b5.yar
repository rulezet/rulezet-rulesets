rule TTP_XOR_QUAD_CurrentVersionRun_00b5 {
  strings:
    $key_00b5 = { 53 da [2] 77 d4 [2] 5c f8 [2] 72 da [2] 66 c1 [2] 69 db [2] 77 c6 [2] 75 c7 [2] 6e c1 [2] 72 c6 [2] 6e e9 }

  condition:
    any of them
}