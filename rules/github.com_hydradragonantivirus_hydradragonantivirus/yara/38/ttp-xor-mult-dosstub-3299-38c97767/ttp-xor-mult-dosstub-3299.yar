rule TTP_XOR_MULT_DOSStub_3299 {
  strings:
    $key_3299 = { 66 f1 [2] 12 e9 [2] 55 eb [2] 12 fa [2] 5c f6 [2] 50 fc [2] 47 f7 [2] 5c b9 [2] 61 }

  condition:
    any of them
}