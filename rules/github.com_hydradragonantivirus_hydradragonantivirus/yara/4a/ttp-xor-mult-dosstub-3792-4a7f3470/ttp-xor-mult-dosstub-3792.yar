rule TTP_XOR_MULT_DOSStub_3792 {
  strings:
    $key_3792 = { 63 fa [2] 17 e2 [2] 50 e0 [2] 17 f1 [2] 59 fd [2] 55 f7 [2] 42 fc [2] 59 b2 [2] 64 }

  condition:
    any of them
}