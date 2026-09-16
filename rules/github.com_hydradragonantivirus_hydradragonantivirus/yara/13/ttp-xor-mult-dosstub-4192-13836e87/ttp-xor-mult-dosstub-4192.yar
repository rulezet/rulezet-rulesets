rule TTP_XOR_MULT_DOSStub_4192 {
  strings:
    $key_4192 = { 15 fa [2] 61 e2 [2] 26 e0 [2] 61 f1 [2] 2f fd [2] 23 f7 [2] 34 fc [2] 2f b2 [2] 12 }

  condition:
    any of them
}