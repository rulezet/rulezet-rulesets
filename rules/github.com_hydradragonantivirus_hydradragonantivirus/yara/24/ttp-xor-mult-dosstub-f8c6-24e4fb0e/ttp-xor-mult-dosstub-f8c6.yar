rule TTP_XOR_MULT_DOSStub_f8c6 {
  strings:
    $key_f8c6 = { ac ae [2] d8 b6 [2] 9f b4 [2] d8 a5 [2] 96 a9 [2] 9a a3 [2] 8d a8 [2] 96 e6 [2] ab }

  condition:
    any of them
}