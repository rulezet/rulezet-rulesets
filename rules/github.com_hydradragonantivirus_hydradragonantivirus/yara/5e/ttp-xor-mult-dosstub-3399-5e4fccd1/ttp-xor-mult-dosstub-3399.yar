rule TTP_XOR_MULT_DOSStub_3399 {
  strings:
    $key_3399 = { 67 f1 [2] 13 e9 [2] 54 eb [2] 13 fa [2] 5d f6 [2] 51 fc [2] 46 f7 [2] 5d b9 [2] 60 }

  condition:
    any of them
}