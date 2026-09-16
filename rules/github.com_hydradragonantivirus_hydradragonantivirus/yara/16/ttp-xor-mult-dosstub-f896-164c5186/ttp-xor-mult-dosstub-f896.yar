rule TTP_XOR_MULT_DOSStub_f896 {
  strings:
    $key_f896 = { ac fe [2] d8 e6 [2] 9f e4 [2] d8 f5 [2] 96 f9 [2] 9a f3 [2] 8d f8 [2] 96 b6 [2] ab }

  condition:
    any of them
}