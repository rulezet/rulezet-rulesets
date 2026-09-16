rule TTP_XOR_MULT_DOSStub_f0b2 {
  strings:
    $key_f0b2 = { a4 da [2] d0 c2 [2] 97 c0 [2] d0 d1 [2] 9e dd [2] 92 d7 [2] 85 dc [2] 9e 92 [2] a3 }

  condition:
    any of them
}