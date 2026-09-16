rule TTP_XOR_MULT_DOSStub_1ec9 {
  strings:
    $key_1ec9 = { 4a a1 [2] 3e b9 [2] 79 bb [2] 3e aa [2] 70 a6 [2] 7c ac [2] 6b a7 [2] 70 e9 [2] 4d }

  condition:
    any of them
}