rule TTP_XOR_QUAD_CurrentVersionRun_6787 {
  strings:
    $key_6787 = { 34 e8 [2] 10 e6 [2] 3b ca [2] 15 e8 [2] 01 f3 [2] 0e e9 [2] 10 f4 [2] 12 f5 [2] 09 f3 [2] 15 f4 [2] 09 db }

  condition:
    any of them
}