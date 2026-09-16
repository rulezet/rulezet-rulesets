rule TTP_XOR_MULT_DOSStub_60b2 {
  strings:
    $key_60b2 = { 34 da [2] 40 c2 [2] 07 c0 [2] 40 d1 [2] 0e dd [2] 02 d7 [2] 15 dc [2] 0e 92 [2] 33 }

  condition:
    any of them
}