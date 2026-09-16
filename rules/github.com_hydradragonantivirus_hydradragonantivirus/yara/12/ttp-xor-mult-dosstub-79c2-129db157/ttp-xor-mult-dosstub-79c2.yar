rule TTP_XOR_MULT_DOSStub_79c2 {
  strings:
    $key_79c2 = { 2d aa [2] 59 b2 [2] 1e b0 [2] 59 a1 [2] 17 ad [2] 1b a7 [2] 0c ac [2] 17 e2 [2] 2a }

  condition:
    any of them
}