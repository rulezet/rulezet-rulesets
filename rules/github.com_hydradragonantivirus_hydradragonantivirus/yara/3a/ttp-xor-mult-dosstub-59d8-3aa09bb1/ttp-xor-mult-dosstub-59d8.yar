rule TTP_XOR_MULT_DOSStub_59d8 {
  strings:
    $key_59d8 = { 0d b0 [2] 79 a8 [2] 3e aa [2] 79 bb [2] 37 b7 [2] 3b bd [2] 2c b6 [2] 37 f8 [2] 0a }

  condition:
    any of them
}