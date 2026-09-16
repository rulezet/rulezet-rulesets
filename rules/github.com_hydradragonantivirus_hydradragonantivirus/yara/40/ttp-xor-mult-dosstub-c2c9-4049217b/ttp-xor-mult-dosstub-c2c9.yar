rule TTP_XOR_MULT_DOSStub_c2c9 {
  strings:
    $key_c2c9 = { 96 a1 [2] e2 b9 [2] a5 bb [2] e2 aa [2] ac a6 [2] a0 ac [2] b7 a7 [2] ac e9 [2] 91 }

  condition:
    any of them
}