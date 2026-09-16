rule TTP_XOR_MULT_DOSStub_f895 {
  strings:
    $key_f895 = { ac fd [2] d8 e5 [2] 9f e7 [2] d8 f6 [2] 96 fa [2] 9a f0 [2] 8d fb [2] 96 b5 [2] ab }

  condition:
    any of them
}