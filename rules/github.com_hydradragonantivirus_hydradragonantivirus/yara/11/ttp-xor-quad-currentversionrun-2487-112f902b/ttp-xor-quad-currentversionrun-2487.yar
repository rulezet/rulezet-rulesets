rule TTP_XOR_QUAD_CurrentVersionRun_2487 {
  strings:
    $key_2487 = { 77 e8 [2] 53 e6 [2] 78 ca [2] 56 e8 [2] 42 f3 [2] 4d e9 [2] 53 f4 [2] 51 f5 [2] 4a f3 [2] 56 f4 [2] 4a db }

  condition:
    any of them
}