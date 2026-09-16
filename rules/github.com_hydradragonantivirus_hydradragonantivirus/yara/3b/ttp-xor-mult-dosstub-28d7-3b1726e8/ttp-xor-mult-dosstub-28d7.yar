rule TTP_XOR_MULT_DOSStub_28d7 {
  strings:
    $key_28d7 = { 7c bf [2] 08 a7 [2] 4f a5 [2] 08 b4 [2] 46 b8 [2] 4a b2 [2] 5d b9 [2] 46 f7 [2] 7b }

  condition:
    any of them
}