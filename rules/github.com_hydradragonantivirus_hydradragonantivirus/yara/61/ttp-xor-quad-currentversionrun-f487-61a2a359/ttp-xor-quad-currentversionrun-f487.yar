rule TTP_XOR_QUAD_CurrentVersionRun_f487 {
  strings:
    $key_f487 = { a7 e8 [2] 83 e6 [2] a8 ca [2] 86 e8 [2] 92 f3 [2] 9d e9 [2] 83 f4 [2] 81 f5 [2] 9a f3 [2] 86 f4 [2] 9a db }

  condition:
    any of them
}