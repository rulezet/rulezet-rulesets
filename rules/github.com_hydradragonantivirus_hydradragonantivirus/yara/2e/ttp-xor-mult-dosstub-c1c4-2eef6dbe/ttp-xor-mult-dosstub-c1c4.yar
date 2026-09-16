rule TTP_XOR_MULT_DOSStub_c1c4 {
  strings:
    $key_c1c4 = { 95 ac [2] e1 b4 [2] a6 b6 [2] e1 a7 [2] af ab [2] a3 a1 [2] b4 aa [2] af e4 [2] 92 }

  condition:
    any of them
}