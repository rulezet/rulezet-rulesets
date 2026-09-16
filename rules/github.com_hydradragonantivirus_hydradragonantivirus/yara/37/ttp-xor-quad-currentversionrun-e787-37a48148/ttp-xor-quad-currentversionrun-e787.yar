rule TTP_XOR_QUAD_CurrentVersionRun_e787 {
  strings:
    $key_e787 = { b4 e8 [2] 90 e6 [2] bb ca [2] 95 e8 [2] 81 f3 [2] 8e e9 [2] 90 f4 [2] 92 f5 [2] 89 f3 [2] 95 f4 [2] 89 db }

  condition:
    any of them
}