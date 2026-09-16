rule TTP_XOR_MULT_DOSStub_0399 {
  strings:
    $key_0399 = { 57 f1 [2] 23 e9 [2] 64 eb [2] 23 fa [2] 6d f6 [2] 61 fc [2] 76 f7 [2] 6d b9 [2] 50 }

  condition:
    any of them
}