rule TTP_XOR_QUAD_CurrentVersionRun_00b4 {
  strings:
    $key_00b4 = { 53 db [2] 77 d5 [2] 5c f9 [2] 72 db [2] 66 c0 [2] 69 da [2] 77 c7 [2] 75 c6 [2] 6e c0 [2] 72 c7 [2] 6e e8 }

  condition:
    any of them
}