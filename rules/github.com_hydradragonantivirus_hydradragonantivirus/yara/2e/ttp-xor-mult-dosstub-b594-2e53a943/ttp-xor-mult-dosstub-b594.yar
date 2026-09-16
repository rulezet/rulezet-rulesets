rule TTP_XOR_MULT_DOSStub_b594 {
  strings:
    $key_b594 = { e1 fc [2] 95 e4 [2] d2 e6 [2] 95 f7 [2] db fb [2] d7 f1 [2] c0 fa [2] db b4 [2] e6 }

  condition:
    any of them
}