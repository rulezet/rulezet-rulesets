rule TTP_XOR_QUAD_CurrentVersionRun_4f87 {
  strings:
    $key_4f87 = { 1c e8 [2] 38 e6 [2] 13 ca [2] 3d e8 [2] 29 f3 [2] 26 e9 [2] 38 f4 [2] 3a f5 [2] 21 f3 [2] 3d f4 [2] 21 db }

  condition:
    any of them
}