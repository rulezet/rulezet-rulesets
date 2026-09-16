rule TTP_XOR_MULT_DOSStub_1799 {
  strings:
    $key_1799 = { 43 f1 [2] 37 e9 [2] 70 eb [2] 37 fa [2] 79 f6 [2] 75 fc [2] 62 f7 [2] 79 b9 [2] 44 }

  condition:
    any of them
}