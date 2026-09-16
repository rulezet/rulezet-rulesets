rule TTP_XOR_MULT_DOSStub_57c9 {
  strings:
    $key_57c9 = { 03 a1 [2] 77 b9 [2] 30 bb [2] 77 aa [2] 39 a6 [2] 35 ac [2] 22 a7 [2] 39 e9 [2] 04 }

  condition:
    any of them
}