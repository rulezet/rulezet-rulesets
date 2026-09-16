rule TTP_XOR_MULT_DOSStub_cfc6 {
  strings:
    $key_cfc6 = { 9b ae [2] ef b6 [2] a8 b4 [2] ef a5 [2] a1 a9 [2] ad a3 [2] ba a8 [2] a1 e6 [2] 9c }

  condition:
    any of them
}