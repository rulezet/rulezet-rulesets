rule TTP_XOR_QUAD_CurrentVersionRun_6287 {
  strings:
    $key_6287 = { 31 e8 [2] 15 e6 [2] 3e ca [2] 10 e8 [2] 04 f3 [2] 0b e9 [2] 15 f4 [2] 17 f5 [2] 0c f3 [2] 10 f4 [2] 0c db }

  condition:
    any of them
}