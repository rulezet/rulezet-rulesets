rule TTP_XOR_QUAD_CurrentVersionRun_1487 {
  strings:
    $key_1487 = { 47 e8 [2] 63 e6 [2] 48 ca [2] 66 e8 [2] 72 f3 [2] 7d e9 [2] 63 f4 [2] 61 f5 [2] 7a f3 [2] 66 f4 [2] 7a db }

  condition:
    any of them
}