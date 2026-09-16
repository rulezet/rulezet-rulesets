rule TTP_XOR_QUAD_CurrentVersionRun_22a8 {
  strings:
    $key_22a8 = { 71 c7 [2] 55 c9 [2] 7e e5 [2] 50 c7 [2] 44 dc [2] 4b c6 [2] 55 db [2] 57 da [2] 4c dc [2] 50 db [2] 4c f4 }

  condition:
    any of them
}