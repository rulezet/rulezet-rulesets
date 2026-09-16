rule TTP_XOR_MULT_DOSStub_4699 {
  strings:
    $key_4699 = { 12 f1 [2] 66 e9 [2] 21 eb [2] 66 fa [2] 28 f6 [2] 24 fc [2] 33 f7 [2] 28 b9 [2] 15 }

  condition:
    any of them
}