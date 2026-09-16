rule TTP_XOR_MULT_DOSStub_49c5 {
  strings:
    $key_49c5 = { 1d ad [2] 69 b5 [2] 2e b7 [2] 69 a6 [2] 27 aa [2] 2b a0 [2] 3c ab [2] 27 e5 [2] 1a }

  condition:
    any of them
}