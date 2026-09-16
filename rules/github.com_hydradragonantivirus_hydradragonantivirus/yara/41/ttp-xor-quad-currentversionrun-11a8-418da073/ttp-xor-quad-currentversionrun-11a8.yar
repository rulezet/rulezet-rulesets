rule TTP_XOR_QUAD_CurrentVersionRun_11a8 {
  strings:
    $key_11a8 = { 42 c7 [2] 66 c9 [2] 4d e5 [2] 63 c7 [2] 77 dc [2] 78 c6 [2] 66 db [2] 64 da [2] 7f dc [2] 63 db [2] 7f f4 }

  condition:
    any of them
}