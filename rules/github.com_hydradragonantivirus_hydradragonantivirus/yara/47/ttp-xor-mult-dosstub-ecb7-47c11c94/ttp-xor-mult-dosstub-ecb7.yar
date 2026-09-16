rule TTP_XOR_MULT_DOSStub_ecb7 {
  strings:
    $key_ecb7 = { b8 df [2] cc c7 [2] 8b c5 [2] cc d4 [2] 82 d8 [2] 8e d2 [2] 99 d9 [2] 82 97 [2] bf }

  condition:
    any of them
}