rule TTP_XOR_MULT_DOSStub_f187 {
  strings:
    $key_f187 = { a5 ef [2] d1 f7 [2] 96 f5 [2] d1 e4 [2] 9f e8 [2] 93 e2 [2] 84 e9 [2] 9f a7 [2] a2 }

  condition:
    any of them
}