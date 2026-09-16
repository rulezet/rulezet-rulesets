rule TTP_XOR_MULT_DOSStub_b599 {
  strings:
    $key_b599 = { e1 f1 [2] 95 e9 [2] d2 eb [2] 95 fa [2] db f6 [2] d7 fc [2] c0 f7 [2] db b9 [2] e6 }

  condition:
    any of them
}