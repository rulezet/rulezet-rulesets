rule TTP_XOR_QUAD_CurrentVersionRun_e987 {
  strings:
    $key_e987 = { ba e8 [2] 9e e6 [2] b5 ca [2] 9b e8 [2] 8f f3 [2] 80 e9 [2] 9e f4 [2] 9c f5 [2] 87 f3 [2] 9b f4 [2] 87 db }

  condition:
    any of them
}