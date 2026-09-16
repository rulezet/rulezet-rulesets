rule TTP_XOR_MULT_DOSStub_6ac2 {
  strings:
    $key_6ac2 = { 3e aa [2] 4a b2 [2] 0d b0 [2] 4a a1 [2] 04 ad [2] 08 a7 [2] 1f ac [2] 04 e2 [2] 39 }

  condition:
    any of them
}