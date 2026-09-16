rule TTP_XOR_MULT_DOSStub_10b2 {
  strings:
    $key_10b2 = { 44 da [2] 30 c2 [2] 77 c0 [2] 30 d1 [2] 7e dd [2] 72 d7 [2] 65 dc [2] 7e 92 [2] 43 }

  condition:
    any of them
}