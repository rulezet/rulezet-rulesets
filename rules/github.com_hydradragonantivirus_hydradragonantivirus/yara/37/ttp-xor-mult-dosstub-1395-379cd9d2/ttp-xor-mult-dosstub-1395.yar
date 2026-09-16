rule TTP_XOR_MULT_DOSStub_1395 {
  strings:
    $key_1395 = { 47 fd [2] 33 e5 [2] 74 e7 [2] 33 f6 [2] 7d fa [2] 71 f0 [2] 66 fb [2] 7d b5 [2] 40 }

  condition:
    any of them
}