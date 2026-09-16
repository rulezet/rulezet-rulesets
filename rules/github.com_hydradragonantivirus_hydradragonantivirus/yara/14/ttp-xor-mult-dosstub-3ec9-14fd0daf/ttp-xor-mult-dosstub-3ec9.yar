rule TTP_XOR_MULT_DOSStub_3ec9 {
  strings:
    $key_3ec9 = { 6a a1 [2] 1e b9 [2] 59 bb [2] 1e aa [2] 50 a6 [2] 5c ac [2] 4b a7 [2] 50 e9 [2] 6d }

  condition:
    any of them
}