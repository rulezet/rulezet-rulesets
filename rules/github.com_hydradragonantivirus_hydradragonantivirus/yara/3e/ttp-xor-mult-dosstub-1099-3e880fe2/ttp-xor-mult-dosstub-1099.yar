rule TTP_XOR_MULT_DOSStub_1099 {
  strings:
    $key_1099 = { 44 f1 [2] 30 e9 [2] 77 eb [2] 30 fa [2] 7e f6 [2] 72 fc [2] 65 f7 [2] 7e b9 [2] 43 }

  condition:
    any of them
}