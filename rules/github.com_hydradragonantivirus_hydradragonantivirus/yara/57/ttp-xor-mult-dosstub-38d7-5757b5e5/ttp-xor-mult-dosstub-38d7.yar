rule TTP_XOR_MULT_DOSStub_38d7 {
  strings:
    $key_38d7 = { 6c bf [2] 18 a7 [2] 5f a5 [2] 18 b4 [2] 56 b8 [2] 5a b2 [2] 4d b9 [2] 56 f7 [2] 6b }

  condition:
    any of them
}