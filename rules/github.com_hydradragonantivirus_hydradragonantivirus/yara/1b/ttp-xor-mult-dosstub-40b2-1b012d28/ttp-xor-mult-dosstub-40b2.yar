rule TTP_XOR_MULT_DOSStub_40b2 {
  strings:
    $key_40b2 = { 14 da [2] 60 c2 [2] 27 c0 [2] 60 d1 [2] 2e dd [2] 22 d7 [2] 35 dc [2] 2e 92 [2] 13 }

  condition:
    any of them
}