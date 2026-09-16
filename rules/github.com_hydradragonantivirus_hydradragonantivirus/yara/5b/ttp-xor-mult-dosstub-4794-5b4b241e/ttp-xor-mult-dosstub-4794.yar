rule TTP_XOR_MULT_DOSStub_4794 {
  strings:
    $key_4794 = { 13 fc [2] 67 e4 [2] 20 e6 [2] 67 f7 [2] 29 fb [2] 25 f1 [2] 32 fa [2] 29 b4 [2] 14 }

  condition:
    any of them
}