rule TTP_XOR_MULT_DOSStub_f1d7 {
  strings:
    $key_f1d7 = { a5 bf [2] d1 a7 [2] 96 a5 [2] d1 b4 [2] 9f b8 [2] 93 b2 [2] 84 b9 [2] 9f f7 [2] a2 }

  condition:
    any of them
}