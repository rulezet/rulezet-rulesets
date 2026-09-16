rule TTP_XOR_MULT_DOSStub_1492 {
  strings:
    $key_1492 = { 40 fa [2] 34 e2 [2] 73 e0 [2] 34 f1 [2] 7a fd [2] 76 f7 [2] 61 fc [2] 7a b2 [2] 47 }

  condition:
    any of them
}