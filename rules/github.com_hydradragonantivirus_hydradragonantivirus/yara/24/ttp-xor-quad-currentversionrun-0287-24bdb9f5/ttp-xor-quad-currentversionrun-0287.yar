rule TTP_XOR_QUAD_CurrentVersionRun_0287 {
  strings:
    $key_0287 = { 51 e8 [2] 75 e6 [2] 5e ca [2] 70 e8 [2] 64 f3 [2] 6b e9 [2] 75 f4 [2] 77 f5 [2] 6c f3 [2] 70 f4 [2] 6c db }

  condition:
    any of them
}