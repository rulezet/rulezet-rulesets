rule TTP_XOR_MULT_DOSStub_6ac4 {
  strings:
    $key_6ac4 = { 3e ac [2] 4a b4 [2] 0d b6 [2] 4a a7 [2] 04 ab [2] 08 a1 [2] 1f aa [2] 04 e4 [2] 39 }

  condition:
    any of them
}