rule TTP_XOR_MULT_DOSStub_6594 {
  strings:
    $key_6594 = { 31 fc [2] 45 e4 [2] 02 e6 [2] 45 f7 [2] 0b fb [2] 07 f1 [2] 10 fa [2] 0b b4 [2] 36 }

  condition:
    any of them
}