rule TTP_XOR_MULT_DOSStub_8494 {
  strings:
    $key_8494 = { d0 fc [2] a4 e4 [2] e3 e6 [2] a4 f7 [2] ea fb [2] e6 f1 [2] f1 fa [2] ea b4 [2] d7 }

  condition:
    any of them
}