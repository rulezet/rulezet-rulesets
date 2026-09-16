rule TTP_XOR_MULT_DOSStub_18d6 {
  strings:
    $key_18d6 = { 4c be [2] 38 a6 [2] 7f a4 [2] 38 b5 [2] 76 b9 [2] 7a b3 [2] 6d b8 [2] 76 f6 [2] 4b }

  condition:
    any of them
}