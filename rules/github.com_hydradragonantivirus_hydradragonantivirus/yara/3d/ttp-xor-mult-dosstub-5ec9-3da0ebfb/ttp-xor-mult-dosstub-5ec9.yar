rule TTP_XOR_MULT_DOSStub_5ec9 {
  strings:
    $key_5ec9 = { 0a a1 [2] 7e b9 [2] 39 bb [2] 7e aa [2] 30 a6 [2] 3c ac [2] 2b a7 [2] 30 e9 [2] 0d }

  condition:
    any of them
}