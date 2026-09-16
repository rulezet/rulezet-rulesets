rule TTP_XOR_MULT_DOSStub_c394 {
  strings:
    $key_c394 = { 97 fc [2] e3 e4 [2] a4 e6 [2] e3 f7 [2] ad fb [2] a1 f1 [2] b6 fa [2] ad b4 [2] 90 }

  condition:
    any of them
}