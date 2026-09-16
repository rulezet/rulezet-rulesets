rule TTP_XOR_MULT_DOSStub_7bc5 {
  strings:
    $key_7bc5 = { 2f ad [2] 5b b5 [2] 1c b7 [2] 5b a6 [2] 15 aa [2] 19 a0 [2] 0e ab [2] 15 e5 [2] 28 }

  condition:
    any of them
}