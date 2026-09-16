rule TTP_XOR_MULT_DOSStub_18d7 {
  strings:
    $key_18d7 = { 4c bf [2] 38 a7 [2] 7f a5 [2] 38 b4 [2] 76 b8 [2] 7a b2 [2] 6d b9 [2] 76 f7 [2] 4b }

  condition:
    any of them
}