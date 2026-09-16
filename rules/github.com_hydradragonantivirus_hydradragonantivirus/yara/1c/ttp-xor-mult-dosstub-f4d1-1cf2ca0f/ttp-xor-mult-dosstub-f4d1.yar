rule TTP_XOR_MULT_DOSStub_f4d1 {
  strings:
    $key_f4d1 = { a0 b9 [2] d4 a1 [2] 93 a3 [2] d4 b2 [2] 9a be [2] 96 b4 [2] 81 bf [2] 9a f1 [2] a7 }

  condition:
    any of them
}