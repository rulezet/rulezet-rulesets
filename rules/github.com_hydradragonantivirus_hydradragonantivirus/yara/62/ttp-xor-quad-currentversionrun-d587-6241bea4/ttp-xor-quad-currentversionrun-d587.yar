rule TTP_XOR_QUAD_CurrentVersionRun_d587 {
  strings:
    $key_d587 = { 86 e8 [2] a2 e6 [2] 89 ca [2] a7 e8 [2] b3 f3 [2] bc e9 [2] a2 f4 [2] a0 f5 [2] bb f3 [2] a7 f4 [2] bb db }

  condition:
    any of them
}