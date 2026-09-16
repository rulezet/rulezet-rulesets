rule TTP_XOR_MULT_DOSStub_f8d6 {
  strings:
    $key_f8d6 = { ac be [2] d8 a6 [2] 9f a4 [2] d8 b5 [2] 96 b9 [2] 9a b3 [2] 8d b8 [2] 96 f6 [2] ab }

  condition:
    any of them
}