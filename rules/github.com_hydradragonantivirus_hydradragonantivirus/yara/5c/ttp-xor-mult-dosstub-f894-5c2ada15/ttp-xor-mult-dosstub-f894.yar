rule TTP_XOR_MULT_DOSStub_f894 {
  strings:
    $key_f894 = { ac fc [2] d8 e4 [2] 9f e6 [2] d8 f7 [2] 96 fb [2] 9a f1 [2] 8d fa [2] 96 b4 [2] ab }

  condition:
    any of them
}