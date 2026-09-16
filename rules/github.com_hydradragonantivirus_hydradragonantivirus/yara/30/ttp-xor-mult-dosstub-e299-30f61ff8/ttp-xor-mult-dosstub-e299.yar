rule TTP_XOR_MULT_DOSStub_e299 {
  strings:
    $key_e299 = { b6 f1 [2] c2 e9 [2] 85 eb [2] c2 fa [2] 8c f6 [2] 80 fc [2] 97 f7 [2] 8c b9 [2] b1 }

  condition:
    any of them
}