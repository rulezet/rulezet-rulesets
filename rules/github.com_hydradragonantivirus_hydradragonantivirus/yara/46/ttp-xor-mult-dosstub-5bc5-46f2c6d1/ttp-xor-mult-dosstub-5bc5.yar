rule TTP_XOR_MULT_DOSStub_5bc5 {
  strings:
    $key_5bc5 = { 0f ad [2] 7b b5 [2] 3c b7 [2] 7b a6 [2] 35 aa [2] 39 a0 [2] 2e ab [2] 35 e5 [2] 08 }

  condition:
    any of them
}