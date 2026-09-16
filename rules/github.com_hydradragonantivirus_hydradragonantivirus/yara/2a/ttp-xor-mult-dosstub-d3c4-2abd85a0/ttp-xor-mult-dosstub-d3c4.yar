rule TTP_XOR_MULT_DOSStub_d3c4 {
  strings:
    $key_d3c4 = { 87 ac [2] f3 b4 [2] b4 b6 [2] f3 a7 [2] bd ab [2] b1 a1 [2] a6 aa [2] bd e4 [2] 80 }

  condition:
    any of them
}