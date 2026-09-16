rule TTP_XOR_QUAD_CurrentVersionRun_02a8 {
  strings:
    $key_02a8 = { 51 c7 [2] 75 c9 [2] 5e e5 [2] 70 c7 [2] 64 dc [2] 6b c6 [2] 75 db [2] 77 da [2] 6c dc [2] 70 db [2] 6c f4 }

  condition:
    any of them
}