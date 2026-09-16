rule TTP_XOR_QUAD_CurrentVersionRun_7b87 {
  strings:
    $key_7b87 = { 28 e8 [2] 0c e6 [2] 27 ca [2] 09 e8 [2] 1d f3 [2] 12 e9 [2] 0c f4 [2] 0e f5 [2] 15 f3 [2] 09 f4 [2] 15 db }

  condition:
    any of them
}