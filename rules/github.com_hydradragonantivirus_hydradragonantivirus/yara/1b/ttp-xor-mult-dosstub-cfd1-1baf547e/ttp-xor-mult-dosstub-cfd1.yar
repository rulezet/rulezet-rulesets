rule TTP_XOR_MULT_DOSStub_cfd1 {
  strings:
    $key_cfd1 = { 9b b9 [2] ef a1 [2] a8 a3 [2] ef b2 [2] a1 be [2] ad b4 [2] ba bf [2] a1 f1 [2] 9c }

  condition:
    any of them
}