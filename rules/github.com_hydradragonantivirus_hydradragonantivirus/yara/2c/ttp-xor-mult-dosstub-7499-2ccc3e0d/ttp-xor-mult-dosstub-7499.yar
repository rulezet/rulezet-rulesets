rule TTP_XOR_MULT_DOSStub_7499 {
  strings:
    $key_7499 = { 20 f1 [2] 54 e9 [2] 13 eb [2] 54 fa [2] 1a f6 [2] 16 fc [2] 01 f7 [2] 1a b9 [2] 27 }

  condition:
    any of them
}