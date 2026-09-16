rule TTP_XOR_MULT_DOSStub_30b2 {
  strings:
    $key_30b2 = { 64 da [2] 10 c2 [2] 57 c0 [2] 10 d1 [2] 5e dd [2] 52 d7 [2] 45 dc [2] 5e 92 [2] 63 }

  condition:
    any of them
}