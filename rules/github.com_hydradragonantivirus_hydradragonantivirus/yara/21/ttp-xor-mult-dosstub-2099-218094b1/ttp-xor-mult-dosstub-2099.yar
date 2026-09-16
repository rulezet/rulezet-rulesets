rule TTP_XOR_MULT_DOSStub_2099 {
  strings:
    $key_2099 = { 74 f1 [2] 00 e9 [2] 47 eb [2] 00 fa [2] 4e f6 [2] 42 fc [2] 55 f7 [2] 4e b9 [2] 73 }

  condition:
    any of them
}