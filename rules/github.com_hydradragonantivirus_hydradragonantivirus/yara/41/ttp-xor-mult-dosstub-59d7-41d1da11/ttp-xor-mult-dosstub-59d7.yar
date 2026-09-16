rule TTP_XOR_MULT_DOSStub_59d7 {
  strings:
    $key_59d7 = { 0d bf [2] 79 a7 [2] 3e a5 [2] 79 b4 [2] 37 b8 [2] 3b b2 [2] 2c b9 [2] 37 f7 [2] 0a }

  condition:
    any of them
}