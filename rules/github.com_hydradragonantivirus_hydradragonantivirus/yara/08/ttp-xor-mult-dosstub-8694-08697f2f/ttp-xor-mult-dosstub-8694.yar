rule TTP_XOR_MULT_DOSStub_8694 {
  strings:
    $key_8694 = { d2 fc [2] a6 e4 [2] e1 e6 [2] a6 f7 [2] e8 fb [2] e4 f1 [2] f3 fa [2] e8 b4 [2] d5 }

  condition:
    any of them
}