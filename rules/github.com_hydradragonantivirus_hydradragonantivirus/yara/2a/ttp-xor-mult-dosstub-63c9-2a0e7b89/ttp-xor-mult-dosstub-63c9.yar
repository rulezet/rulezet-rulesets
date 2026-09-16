rule TTP_XOR_MULT_DOSStub_63c9 {
  strings:
    $key_63c9 = { 37 a1 [2] 43 b9 [2] 04 bb [2] 43 aa [2] 0d a6 [2] 01 ac [2] 16 a7 [2] 0d e9 [2] 30 }

  condition:
    any of them
}