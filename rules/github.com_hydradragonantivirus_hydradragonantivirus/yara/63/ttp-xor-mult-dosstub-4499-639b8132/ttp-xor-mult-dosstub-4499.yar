rule TTP_XOR_MULT_DOSStub_4499 {
  strings:
    $key_4499 = { 10 f1 [2] 64 e9 [2] 23 eb [2] 64 fa [2] 2a f6 [2] 26 fc [2] 31 f7 [2] 2a b9 [2] 17 }

  condition:
    any of them
}