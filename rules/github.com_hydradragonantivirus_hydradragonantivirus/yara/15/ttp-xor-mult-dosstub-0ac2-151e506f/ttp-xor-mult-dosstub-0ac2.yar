rule TTP_XOR_MULT_DOSStub_0ac2 {
  strings:
    $key_0ac2 = { 5e aa [2] 2a b2 [2] 6d b0 [2] 2a a1 [2] 64 ad [2] 68 a7 [2] 7f ac [2] 64 e2 [2] 59 }

  condition:
    any of them
}