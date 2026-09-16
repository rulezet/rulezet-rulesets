rule TTP_XOR_MULT_DOSStub_59c5 {
  strings:
    $key_59c5 = { 0d ad [2] 79 b5 [2] 3e b7 [2] 79 a6 [2] 37 aa [2] 3b a0 [2] 2c ab [2] 37 e5 [2] 0a }

  condition:
    any of them
}