rule TTP_XOR_QUAD_CurrentVersionRun_2f87 {
  strings:
    $key_2f87 = { 7c e8 [2] 58 e6 [2] 73 ca [2] 5d e8 [2] 49 f3 [2] 46 e9 [2] 58 f4 [2] 5a f5 [2] 41 f3 [2] 5d f4 [2] 41 db }

  condition:
    any of them
}