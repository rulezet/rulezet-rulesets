rule TTP_XOR_QUAD_CurrentVersionRun_41a8 {
  strings:
    $key_41a8 = { 12 c7 [2] 36 c9 [2] 1d e5 [2] 33 c7 [2] 27 dc [2] 28 c6 [2] 36 db [2] 34 da [2] 2f dc [2] 33 db [2] 2f f4 }

  condition:
    any of them
}