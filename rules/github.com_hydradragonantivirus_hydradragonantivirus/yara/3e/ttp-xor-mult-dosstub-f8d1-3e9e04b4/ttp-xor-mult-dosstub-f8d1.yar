rule TTP_XOR_MULT_DOSStub_f8d1 {
  strings:
    $key_f8d1 = { ac b9 [2] d8 a1 [2] 9f a3 [2] d8 b2 [2] 96 be [2] 9a b4 [2] 8d bf [2] 96 f1 [2] ab }

  condition:
    any of them
}