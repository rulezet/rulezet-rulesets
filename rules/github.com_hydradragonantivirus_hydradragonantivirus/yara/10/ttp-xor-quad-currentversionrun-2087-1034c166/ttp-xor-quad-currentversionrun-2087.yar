rule TTP_XOR_QUAD_CurrentVersionRun_2087 {
  strings:
    $key_2087 = { 73 e8 [2] 57 e6 [2] 7c ca [2] 52 e8 [2] 46 f3 [2] 49 e9 [2] 57 f4 [2] 55 f5 [2] 4e f3 [2] 52 f4 [2] 4e db }

  condition:
    any of them
}