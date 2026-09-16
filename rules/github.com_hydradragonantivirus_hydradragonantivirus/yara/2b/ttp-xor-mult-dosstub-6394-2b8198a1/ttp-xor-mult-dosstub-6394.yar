rule TTP_XOR_MULT_DOSStub_6394 {
  strings:
    $key_6394 = { 37 fc [2] 43 e4 [2] 04 e6 [2] 43 f7 [2] 0d fb [2] 01 f1 [2] 16 fa [2] 0d b4 [2] 30 }

  condition:
    any of them
}