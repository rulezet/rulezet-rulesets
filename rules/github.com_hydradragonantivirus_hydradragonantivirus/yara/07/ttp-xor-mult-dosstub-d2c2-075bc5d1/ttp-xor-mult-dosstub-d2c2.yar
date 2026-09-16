rule TTP_XOR_MULT_DOSStub_d2c2 {
  strings:
    $key_d2c2 = { 86 aa [2] f2 b2 [2] b5 b0 [2] f2 a1 [2] bc ad [2] b0 a7 [2] a7 ac [2] bc e2 [2] 81 }

  condition:
    any of them
}