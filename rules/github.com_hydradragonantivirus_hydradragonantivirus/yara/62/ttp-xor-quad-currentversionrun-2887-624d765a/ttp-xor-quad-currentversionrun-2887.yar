rule TTP_XOR_QUAD_CurrentVersionRun_2887 {
  strings:
    $key_2887 = { 7b e8 [2] 5f e6 [2] 74 ca [2] 5a e8 [2] 4e f3 [2] 41 e9 [2] 5f f4 [2] 5d f5 [2] 46 f3 [2] 5a f4 [2] 46 db }

  condition:
    any of them
}