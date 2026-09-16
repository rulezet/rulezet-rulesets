rule TTP_XOR_MULT_DOSStub_e694 {
  strings:
    $key_e694 = { b2 fc [2] c6 e4 [2] 81 e6 [2] c6 f7 [2] 88 fb [2] 84 f1 [2] 93 fa [2] 88 b4 [2] b5 }

  condition:
    any of them
}