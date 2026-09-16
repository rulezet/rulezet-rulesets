rule TTP_XOR_MULT_DOSStub_4299 {
  strings:
    $key_4299 = { 16 f1 [2] 62 e9 [2] 25 eb [2] 62 fa [2] 2c f6 [2] 20 fc [2] 37 f7 [2] 2c b9 [2] 11 }

  condition:
    any of them
}