rule TTP_XOR_MULT_DOSStub_f594 {
  strings:
    $key_f594 = { a1 fc [2] d5 e4 [2] 92 e6 [2] d5 f7 [2] 9b fb [2] 97 f1 [2] 80 fa [2] 9b b4 [2] a6 }

  condition:
    any of them
}