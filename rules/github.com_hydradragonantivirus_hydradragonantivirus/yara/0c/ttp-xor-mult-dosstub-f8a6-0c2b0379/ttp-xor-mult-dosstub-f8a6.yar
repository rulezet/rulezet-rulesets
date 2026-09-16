rule TTP_XOR_MULT_DOSStub_f8a6 {
  strings:
    $key_f8a6 = { ac ce [2] d8 d6 [2] 9f d4 [2] d8 c5 [2] 96 c9 [2] 9a c3 [2] 8d c8 [2] 96 86 [2] ab }

  condition:
    any of them
}