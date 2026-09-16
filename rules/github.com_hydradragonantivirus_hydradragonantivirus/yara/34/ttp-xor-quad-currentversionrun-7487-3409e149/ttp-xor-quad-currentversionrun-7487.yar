rule TTP_XOR_QUAD_CurrentVersionRun_7487 {
  strings:
    $key_7487 = { 27 e8 [2] 03 e6 [2] 28 ca [2] 06 e8 [2] 12 f3 [2] 1d e9 [2] 03 f4 [2] 01 f5 [2] 1a f3 [2] 06 f4 [2] 1a db }

  condition:
    any of them
}