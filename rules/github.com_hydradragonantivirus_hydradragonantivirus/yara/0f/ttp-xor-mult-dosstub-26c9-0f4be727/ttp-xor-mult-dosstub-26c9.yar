rule TTP_XOR_MULT_DOSStub_26c9 {
  strings:
    $key_26c9 = { 72 a1 [2] 06 b9 [2] 41 bb [2] 06 aa [2] 48 a6 [2] 44 ac [2] 53 a7 [2] 48 e9 [2] 75 }

  condition:
    any of them
}