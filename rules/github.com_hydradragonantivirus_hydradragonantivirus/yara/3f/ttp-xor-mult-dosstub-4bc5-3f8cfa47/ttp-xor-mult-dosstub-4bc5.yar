rule TTP_XOR_MULT_DOSStub_4bc5 {
  strings:
    $key_4bc5 = { 1f ad [2] 6b b5 [2] 2c b7 [2] 6b a6 [2] 25 aa [2] 29 a0 [2] 3e ab [2] 25 e5 [2] 18 }

  condition:
    any of them
}