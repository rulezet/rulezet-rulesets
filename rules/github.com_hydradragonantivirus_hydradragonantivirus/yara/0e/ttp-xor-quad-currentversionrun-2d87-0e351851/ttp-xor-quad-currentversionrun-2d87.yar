rule TTP_XOR_QUAD_CurrentVersionRun_2d87 {
  strings:
    $key_2d87 = { 7e e8 [2] 5a e6 [2] 71 ca [2] 5f e8 [2] 4b f3 [2] 44 e9 [2] 5a f4 [2] 58 f5 [2] 43 f3 [2] 5f f4 [2] 43 db }

  condition:
    any of them
}