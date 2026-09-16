rule TTP_XOR_MULT_DOSStub_59d6 {
  strings:
    $key_59d6 = { 0d be [2] 79 a6 [2] 3e a4 [2] 79 b5 [2] 37 b9 [2] 3b b3 [2] 2c b8 [2] 37 f6 [2] 0a }

  condition:
    any of them
}