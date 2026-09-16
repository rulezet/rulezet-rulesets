rule TTP_XOR_MULT_DOSStub_5592 {
  strings:
    $key_5592 = { 01 fa [2] 75 e2 [2] 32 e0 [2] 75 f1 [2] 3b fd [2] 37 f7 [2] 20 fc [2] 3b b2 [2] 06 }

  condition:
    any of them
}