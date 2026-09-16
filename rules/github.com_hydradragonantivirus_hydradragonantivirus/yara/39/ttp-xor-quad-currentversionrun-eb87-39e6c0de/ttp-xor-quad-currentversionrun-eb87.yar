rule TTP_XOR_QUAD_CurrentVersionRun_eb87 {
  strings:
    $key_eb87 = { b8 e8 [2] 9c e6 [2] b7 ca [2] 99 e8 [2] 8d f3 [2] 82 e9 [2] 9c f4 [2] 9e f5 [2] 85 f3 [2] 99 f4 [2] 85 db }

  condition:
    any of them
}