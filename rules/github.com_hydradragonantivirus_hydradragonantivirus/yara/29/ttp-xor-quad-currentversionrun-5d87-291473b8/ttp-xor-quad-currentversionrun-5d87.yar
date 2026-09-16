rule TTP_XOR_QUAD_CurrentVersionRun_5d87 {
  strings:
    $key_5d87 = { 0e e8 [2] 2a e6 [2] 01 ca [2] 2f e8 [2] 3b f3 [2] 34 e9 [2] 2a f4 [2] 28 f5 [2] 33 f3 [2] 2f f4 [2] 33 db }

  condition:
    any of them
}