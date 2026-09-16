rule TTP_XOR_MULT_DOSStub_1bc5 {
  strings:
    $key_1bc5 = { 4f ad [2] 3b b5 [2] 7c b7 [2] 3b a6 [2] 75 aa [2] 79 a0 [2] 6e ab [2] 75 e5 [2] 48 }

  condition:
    any of them
}