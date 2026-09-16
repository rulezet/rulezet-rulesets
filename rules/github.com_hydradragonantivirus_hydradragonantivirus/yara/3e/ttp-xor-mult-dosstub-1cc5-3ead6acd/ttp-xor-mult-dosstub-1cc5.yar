rule TTP_XOR_MULT_DOSStub_1cc5 {
  strings:
    $key_1cc5 = { 48 ad [2] 3c b5 [2] 7b b7 [2] 3c a6 [2] 72 aa [2] 7e a0 [2] 69 ab [2] 72 e5 [2] 4f }

  condition:
    any of them
}