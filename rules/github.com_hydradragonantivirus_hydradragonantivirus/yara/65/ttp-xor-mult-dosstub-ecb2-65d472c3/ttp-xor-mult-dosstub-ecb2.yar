rule TTP_XOR_MULT_DOSStub_ecb2 {
  strings:
    $key_ecb2 = { b8 da [2] cc c2 [2] 8b c0 [2] cc d1 [2] 82 dd [2] 8e d7 [2] 99 dc [2] 82 92 [2] bf }

  condition:
    any of them
}