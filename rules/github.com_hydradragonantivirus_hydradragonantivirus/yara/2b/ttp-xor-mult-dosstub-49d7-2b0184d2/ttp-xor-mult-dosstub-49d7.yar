rule TTP_XOR_MULT_DOSStub_49d7 {
  strings:
    $key_49d7 = { 1d bf [2] 69 a7 [2] 2e a5 [2] 69 b4 [2] 27 b8 [2] 2b b2 [2] 3c b9 [2] 27 f7 [2] 1a }

  condition:
    any of them
}