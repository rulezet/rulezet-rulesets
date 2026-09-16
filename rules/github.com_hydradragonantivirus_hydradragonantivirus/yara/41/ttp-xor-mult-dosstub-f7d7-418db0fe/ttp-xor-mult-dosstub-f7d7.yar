rule TTP_XOR_MULT_DOSStub_f7d7 {
  strings:
    $key_f7d7 = { a3 bf [2] d7 a7 [2] 90 a5 [2] d7 b4 [2] 99 b8 [2] 95 b2 [2] 82 b9 [2] 99 f7 [2] a4 }

  condition:
    any of them
}