rule TTP_XOR_MULT_DOSStub_49d6 {
  strings:
    $key_49d6 = { 1d be [2] 69 a6 [2] 2e a4 [2] 69 b5 [2] 27 b9 [2] 2b b3 [2] 3c b8 [2] 27 f6 [2] 1a }

  condition:
    any of them
}