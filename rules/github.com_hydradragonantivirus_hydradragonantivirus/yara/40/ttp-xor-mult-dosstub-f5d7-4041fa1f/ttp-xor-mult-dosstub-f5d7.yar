rule TTP_XOR_MULT_DOSStub_f5d7 {
  strings:
    $key_f5d7 = { a1 bf [2] d5 a7 [2] 92 a5 [2] d5 b4 [2] 9b b8 [2] 97 b2 [2] 80 b9 [2] 9b f7 [2] a6 }

  condition:
    any of them
}