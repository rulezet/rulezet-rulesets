rule TTP_XOR_MULT_DOSStub_7792 {
  strings:
    $key_7792 = { 23 fa [2] 57 e2 [2] 10 e0 [2] 57 f1 [2] 19 fd [2] 15 f7 [2] 02 fc [2] 19 b2 [2] 24 }

  condition:
    any of them
}