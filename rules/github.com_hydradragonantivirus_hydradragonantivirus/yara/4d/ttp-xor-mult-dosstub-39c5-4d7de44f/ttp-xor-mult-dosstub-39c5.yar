rule TTP_XOR_MULT_DOSStub_39c5 {
  strings:
    $key_39c5 = { 6d ad [2] 19 b5 [2] 5e b7 [2] 19 a6 [2] 57 aa [2] 5b a0 [2] 4c ab [2] 57 e5 [2] 6a }

  condition:
    any of them
}