rule TTP_XOR_MULT_DOSStub_0394 {
  strings:
    $key_0394 = { 57 fc [2] 23 e4 [2] 64 e6 [2] 23 f7 [2] 6d fb [2] 61 f1 [2] 76 fa [2] 6d b4 [2] 50 }

  condition:
    any of them
}