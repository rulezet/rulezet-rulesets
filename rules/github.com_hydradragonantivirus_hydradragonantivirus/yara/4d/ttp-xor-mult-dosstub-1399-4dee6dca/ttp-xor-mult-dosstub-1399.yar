rule TTP_XOR_MULT_DOSStub_1399 {
  strings:
    $key_1399 = { 47 f1 [2] 33 e9 [2] 74 eb [2] 33 fa [2] 7d f6 [2] 71 fc [2] 66 f7 [2] 7d b9 [2] 40 }

  condition:
    any of them
}