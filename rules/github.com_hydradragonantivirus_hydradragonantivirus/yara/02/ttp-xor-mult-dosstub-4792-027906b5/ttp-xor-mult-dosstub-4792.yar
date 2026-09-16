rule TTP_XOR_MULT_DOSStub_4792 {
  strings:
    $key_4792 = { 13 fa [2] 67 e2 [2] 20 e0 [2] 67 f1 [2] 29 fd [2] 25 f7 [2] 32 fc [2] 29 b2 [2] 14 }

  condition:
    any of them
}