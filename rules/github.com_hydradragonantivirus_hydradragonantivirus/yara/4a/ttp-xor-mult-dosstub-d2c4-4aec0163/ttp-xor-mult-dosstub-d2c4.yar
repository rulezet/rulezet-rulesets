rule TTP_XOR_MULT_DOSStub_d2c4 {
  strings:
    $key_d2c4 = { 86 ac [2] f2 b4 [2] b5 b6 [2] f2 a7 [2] bc ab [2] b0 a1 [2] a7 aa [2] bc e4 [2] 81 }

  condition:
    any of them
}