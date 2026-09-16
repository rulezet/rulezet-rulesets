rule TTP_XOR_MULT_DOSStub_ecb6 {
  strings:
    $key_ecb6 = { b8 de [2] cc c6 [2] 8b c4 [2] cc d5 [2] 82 d9 [2] 8e d3 [2] 99 d8 [2] 82 96 [2] bf }

  condition:
    any of them
}