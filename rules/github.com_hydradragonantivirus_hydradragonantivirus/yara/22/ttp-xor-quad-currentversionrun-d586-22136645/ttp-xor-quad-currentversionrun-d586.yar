rule TTP_XOR_QUAD_CurrentVersionRun_d586 {
  strings:
    $key_d586 = { 86 e9 [2] a2 e7 [2] 89 cb [2] a7 e9 [2] b3 f2 [2] bc e8 [2] a2 f5 [2] a0 f4 [2] bb f2 [2] a7 f5 [2] bb da }

  condition:
    any of them
}