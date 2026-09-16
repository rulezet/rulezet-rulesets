rule TTP_XOR_MULT_DOSStub_f1c7 {
  strings:
    $key_f1c7 = { a5 af [2] d1 b7 [2] 96 b5 [2] d1 a4 [2] 9f a8 [2] 93 a2 [2] 84 a9 [2] 9f e7 [2] a2 }

  condition:
    any of them
}