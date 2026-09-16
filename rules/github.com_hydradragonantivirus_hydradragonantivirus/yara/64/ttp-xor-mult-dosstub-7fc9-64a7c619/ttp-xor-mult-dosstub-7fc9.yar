rule TTP_XOR_MULT_DOSStub_7fc9 {
  strings:
    $key_7fc9 = { 2b a1 [2] 5f b9 [2] 18 bb [2] 5f aa [2] 11 a6 [2] 1d ac [2] 0a a7 [2] 11 e9 [2] 2c }

  condition:
    any of them
}