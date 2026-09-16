rule TTP_XOR_QUAD_CurrentVersionRun_f4a8 {
  strings:
    $key_f4a8 = { a7 c7 [2] 83 c9 [2] a8 e5 [2] 86 c7 [2] 92 dc [2] 9d c6 [2] 83 db [2] 81 da [2] 9a dc [2] 86 db [2] 9a f4 }

  condition:
    any of them
}