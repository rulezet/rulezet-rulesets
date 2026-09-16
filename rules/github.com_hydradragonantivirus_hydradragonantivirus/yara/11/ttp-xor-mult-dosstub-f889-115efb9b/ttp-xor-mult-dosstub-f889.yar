rule TTP_XOR_MULT_DOSStub_f889 {
  strings:
    $key_f889 = { ac e1 [2] d8 f9 [2] 9f fb [2] d8 ea [2] 96 e6 [2] 9a ec [2] 8d e7 [2] 96 a9 [2] ab }

  condition:
    any of them
}