rule TTP_XOR_MULT_DOSStub_ecb4 {
  strings:
    $key_ecb4 = { b8 dc [2] cc c4 [2] 8b c6 [2] cc d7 [2] 82 db [2] 8e d1 [2] 99 da [2] 82 94 [2] bf }

  condition:
    any of them
}