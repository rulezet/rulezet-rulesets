rule TTP_XOR_MULT_DOSStub_0099 {
  strings:
    $key_0099 = { 54 f1 [2] 20 e9 [2] 67 eb [2] 20 fa [2] 6e f6 [2] 62 fc [2] 75 f7 [2] 6e b9 [2] 53 }

  condition:
    any of them
}