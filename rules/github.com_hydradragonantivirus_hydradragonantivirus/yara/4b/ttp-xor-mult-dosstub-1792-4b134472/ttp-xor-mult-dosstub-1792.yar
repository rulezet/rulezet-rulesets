rule TTP_XOR_MULT_DOSStub_1792 {
  strings:
    $key_1792 = { 43 fa [2] 37 e2 [2] 70 e0 [2] 37 f1 [2] 79 fd [2] 75 f7 [2] 62 fc [2] 79 b2 [2] 44 }

  condition:
    any of them
}