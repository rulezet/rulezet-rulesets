rule TTP_XOR_MULT_DOSStub_f5d1 {
  strings:
    $key_f5d1 = { a1 b9 [2] d5 a1 [2] 92 a3 [2] d5 b2 [2] 9b be [2] 97 b4 [2] 80 bf [2] 9b f1 [2] a6 }

  condition:
    any of them
}