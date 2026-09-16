rule TTP_XOR_QUAD_CurrentVersionRun_6487 {
  strings:
    $key_6487 = { 37 e8 [2] 13 e6 [2] 38 ca [2] 16 e8 [2] 02 f3 [2] 0d e9 [2] 13 f4 [2] 11 f5 [2] 0a f3 [2] 16 f4 [2] 0a db }

  condition:
    any of them
}