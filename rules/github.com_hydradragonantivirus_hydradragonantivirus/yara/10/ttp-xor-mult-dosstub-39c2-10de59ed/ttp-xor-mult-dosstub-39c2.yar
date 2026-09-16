rule TTP_XOR_MULT_DOSStub_39c2 {
  strings:
    $key_39c2 = { 6d aa [2] 19 b2 [2] 5e b0 [2] 19 a1 [2] 57 ad [2] 5b a7 [2] 4c ac [2] 57 e2 [2] 6a }

  condition:
    any of them
}