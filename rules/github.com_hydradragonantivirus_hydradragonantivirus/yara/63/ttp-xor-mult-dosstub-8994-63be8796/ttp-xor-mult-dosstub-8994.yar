rule TTP_XOR_MULT_DOSStub_8994 {
  strings:
    $key_8994 = { dd fc [2] a9 e4 [2] ee e6 [2] a9 f7 [2] e7 fb [2] eb f1 [2] fc fa [2] e7 b4 [2] da }

  condition:
    any of them
}