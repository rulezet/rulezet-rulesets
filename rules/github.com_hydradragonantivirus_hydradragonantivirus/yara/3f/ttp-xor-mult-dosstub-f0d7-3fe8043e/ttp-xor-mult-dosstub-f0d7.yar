rule TTP_XOR_MULT_DOSStub_f0d7 {
  strings:
    $key_f0d7 = { a4 bf [2] d0 a7 [2] 97 a5 [2] d0 b4 [2] 9e b8 [2] 92 b2 [2] 85 b9 [2] 9e f7 [2] a3 }

  condition:
    any of them
}