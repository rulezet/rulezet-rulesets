rule TTP_XOR_QUAD_CurrentVersionRun_4b87 {
  strings:
    $key_4b87 = { 18 e8 [2] 3c e6 [2] 17 ca [2] 39 e8 [2] 2d f3 [2] 22 e9 [2] 3c f4 [2] 3e f5 [2] 25 f3 [2] 39 f4 [2] 25 db }

  condition:
    any of them
}