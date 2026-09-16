rule TTP_XOR_QUAD_CurrentVersionRun_cea5 {
  strings:
    $key_cea5 = { 9d ca [2] b9 c4 [2] 92 e8 [2] bc ca [2] a8 d1 [2] a7 cb [2] b9 d6 [2] bb d7 [2] a0 d1 [2] bc d6 [2] a0 f9 }

  condition:
    any of them
}