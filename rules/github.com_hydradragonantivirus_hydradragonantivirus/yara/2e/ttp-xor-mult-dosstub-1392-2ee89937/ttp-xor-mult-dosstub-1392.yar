rule TTP_XOR_MULT_DOSStub_1392 {
  strings:
    $key_1392 = { 47 fa [2] 33 e2 [2] 74 e0 [2] 33 f1 [2] 7d fd [2] 71 f7 [2] 66 fc [2] 7d b2 [2] 40 }

  condition:
    any of them
}