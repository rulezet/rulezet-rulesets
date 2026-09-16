rule TTP_XOR_MULT_DOSStub_cfc7 {
  strings:
    $key_cfc7 = { 9b af [2] ef b7 [2] a8 b5 [2] ef a4 [2] a1 a8 [2] ad a2 [2] ba a9 [2] a1 e7 [2] 9c }

  condition:
    any of them
}