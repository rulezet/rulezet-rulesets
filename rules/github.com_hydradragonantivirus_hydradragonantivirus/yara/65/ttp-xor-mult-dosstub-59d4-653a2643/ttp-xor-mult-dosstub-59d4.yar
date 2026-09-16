rule TTP_XOR_MULT_DOSStub_59d4 {
  strings:
    $key_59d4 = { 0d bc [2] 79 a4 [2] 3e a6 [2] 79 b7 [2] 37 bb [2] 3b b1 [2] 2c ba [2] 37 f4 [2] 0a }

  condition:
    any of them
}