rule TTP_XOR_MULT_DOSStub_f4d6 {
  strings:
    $key_f4d6 = { a0 be [2] d4 a6 [2] 93 a4 [2] d4 b5 [2] 9a b9 [2] 96 b3 [2] 81 b8 [2] 9a f6 [2] a7 }

  condition:
    any of them
}