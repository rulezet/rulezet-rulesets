rule TTP_XOR_QUAD_CurrentVersionRun_2b87 {
  strings:
    $key_2b87 = { 78 e8 [2] 5c e6 [2] 77 ca [2] 59 e8 [2] 4d f3 [2] 42 e9 [2] 5c f4 [2] 5e f5 [2] 45 f3 [2] 59 f4 [2] 45 db }

  condition:
    any of them
}