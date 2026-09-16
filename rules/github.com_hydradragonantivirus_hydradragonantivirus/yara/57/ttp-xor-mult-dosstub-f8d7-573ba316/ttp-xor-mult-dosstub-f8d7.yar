rule TTP_XOR_MULT_DOSStub_f8d7 {
  strings:
    $key_f8d7 = { ac bf [2] d8 a7 [2] 9f a5 [2] d8 b4 [2] 96 b8 [2] 9a b2 [2] 8d b9 [2] 96 f7 [2] ab }

  condition:
    any of them
}