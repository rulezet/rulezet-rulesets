rule TTP_XOR_MULT_DOSStub_5594 {
  strings:
    $key_5594 = { 01 fc [2] 75 e4 [2] 32 e6 [2] 75 f7 [2] 3b fb [2] 37 f1 [2] 20 fa [2] 3b b4 [2] 06 }

  condition:
    any of them
}