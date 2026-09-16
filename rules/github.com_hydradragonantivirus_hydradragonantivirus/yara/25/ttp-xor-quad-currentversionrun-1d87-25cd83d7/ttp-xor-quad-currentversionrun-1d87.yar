rule TTP_XOR_QUAD_CurrentVersionRun_1d87 {
  strings:
    $key_1d87 = { 4e e8 [2] 6a e6 [2] 41 ca [2] 6f e8 [2] 7b f3 [2] 74 e9 [2] 6a f4 [2] 68 f5 [2] 73 f3 [2] 6f f4 [2] 73 db }

  condition:
    any of them
}