rule TTP_XOR_QUAD_CurrentVersionRun_74a8 {
  strings:
    $key_74a8 = { 27 c7 [2] 03 c9 [2] 28 e5 [2] 06 c7 [2] 12 dc [2] 1d c6 [2] 03 db [2] 01 da [2] 1a dc [2] 06 db [2] 1a f4 }

  condition:
    any of them
}