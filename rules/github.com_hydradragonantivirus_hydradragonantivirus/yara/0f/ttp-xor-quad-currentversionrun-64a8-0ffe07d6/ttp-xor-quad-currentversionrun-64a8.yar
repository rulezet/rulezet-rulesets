rule TTP_XOR_QUAD_CurrentVersionRun_64a8 {
  strings:
    $key_64a8 = { 37 c7 [2] 13 c9 [2] 38 e5 [2] 16 c7 [2] 02 dc [2] 0d c6 [2] 13 db [2] 11 da [2] 0a dc [2] 16 db [2] 0a f4 }

  condition:
    any of them
}