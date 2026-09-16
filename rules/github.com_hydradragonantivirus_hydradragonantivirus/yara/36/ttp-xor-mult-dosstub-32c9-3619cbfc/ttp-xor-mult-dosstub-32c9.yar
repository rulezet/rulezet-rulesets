rule TTP_XOR_MULT_DOSStub_32c9 {
  strings:
    $key_32c9 = { 66 a1 [2] 12 b9 [2] 55 bb [2] 12 aa [2] 5c a6 [2] 50 ac [2] 47 a7 [2] 5c e9 [2] 61 }

  condition:
    any of them
}