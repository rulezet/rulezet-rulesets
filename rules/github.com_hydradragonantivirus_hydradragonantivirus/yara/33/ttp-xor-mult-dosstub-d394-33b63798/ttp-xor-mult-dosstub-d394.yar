rule TTP_XOR_MULT_DOSStub_d394 {
  strings:
    $key_d394 = { 87 fc [2] f3 e4 [2] b4 e6 [2] f3 f7 [2] bd fb [2] b1 f1 [2] a6 fa [2] bd b4 [2] 80 }

  condition:
    any of them
}