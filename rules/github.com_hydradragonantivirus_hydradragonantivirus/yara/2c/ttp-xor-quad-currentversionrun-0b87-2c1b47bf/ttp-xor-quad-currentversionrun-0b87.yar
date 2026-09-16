rule TTP_XOR_QUAD_CurrentVersionRun_0b87 {
  strings:
    $key_0b87 = { 58 e8 [2] 7c e6 [2] 57 ca [2] 79 e8 [2] 6d f3 [2] 62 e9 [2] 7c f4 [2] 7e f5 [2] 65 f3 [2] 79 f4 [2] 65 db }

  condition:
    any of them
}