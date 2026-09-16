rule TTP_XOR_MULT_DOSStub_59d5 {
  strings:
    $key_59d5 = { 0d bd [2] 79 a5 [2] 3e a7 [2] 79 b6 [2] 37 ba [2] 3b b0 [2] 2c bb [2] 37 f5 [2] 0a }

  condition:
    any of them
}