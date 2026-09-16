rule TTP_XOR_MULT_DOSStub_f8d5 {
  strings:
    $key_f8d5 = { ac bd [2] d8 a5 [2] 9f a7 [2] d8 b6 [2] 96 ba [2] 9a b0 [2] 8d bb [2] 96 f5 [2] ab }

  condition:
    any of them
}