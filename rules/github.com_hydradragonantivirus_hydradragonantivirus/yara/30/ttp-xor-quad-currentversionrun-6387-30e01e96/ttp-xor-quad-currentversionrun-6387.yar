rule TTP_XOR_QUAD_CurrentVersionRun_6387 {
  strings:
    $key_6387 = { 30 e8 [2] 14 e6 [2] 3f ca [2] 11 e8 [2] 05 f3 [2] 0a e9 [2] 14 f4 [2] 16 f5 [2] 0d f3 [2] 11 f4 [2] 0d db }

  condition:
    any of them
}