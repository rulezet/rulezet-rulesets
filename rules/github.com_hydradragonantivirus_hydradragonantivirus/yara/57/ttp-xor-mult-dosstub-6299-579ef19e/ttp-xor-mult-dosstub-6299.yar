rule TTP_XOR_MULT_DOSStub_6299 {
  strings:
    $key_6299 = { 36 f1 [2] 42 e9 [2] 05 eb [2] 42 fa [2] 0c f6 [2] 00 fc [2] 17 f7 [2] 0c b9 [2] 31 }

  condition:
    any of them
}