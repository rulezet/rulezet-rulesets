rule TTP_XOR_MULT_DOSStub_2ac2 {
  strings:
    $key_2ac2 = { 7e aa [2] 0a b2 [2] 4d b0 [2] 0a a1 [2] 44 ad [2] 48 a7 [2] 5f ac [2] 44 e2 [2] 79 }

  condition:
    any of them
}