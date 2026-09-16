rule TTP_XOR_MULT_DOSStub_0592 {
  strings:
    $key_0592 = { 51 fa [2] 25 e2 [2] 62 e0 [2] 25 f1 [2] 6b fd [2] 67 f7 [2] 70 fc [2] 6b b2 [2] 56 }

  condition:
    any of them
}