rule TTP_XOR_MULT_DOSStub_ecb5 {
  strings:
    $key_ecb5 = { b8 dd [2] cc c5 [2] 8b c7 [2] cc d6 [2] 82 da [2] 8e d0 [2] 99 db [2] 82 95 [2] bf }

  condition:
    any of them
}