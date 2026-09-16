rule TTP_XOR_MULT_DOSStub_d2c9 {
  strings:
    $key_d2c9 = { 86 a1 [2] f2 b9 [2] b5 bb [2] f2 aa [2] bc a6 [2] b0 ac [2] a7 a7 [2] bc e9 [2] 81 }

  condition:
    any of them
}