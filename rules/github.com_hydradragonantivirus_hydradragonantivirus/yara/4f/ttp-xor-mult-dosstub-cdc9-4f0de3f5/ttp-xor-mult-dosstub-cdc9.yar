rule TTP_XOR_MULT_DOSStub_cdc9 {
  strings:
    $key_cdc9 = { 99 a1 [2] ed b9 [2] aa bb [2] ed aa [2] a3 a6 [2] af ac [2] b8 a7 [2] a3 e9 [2] 9e }

  condition:
    any of them
}