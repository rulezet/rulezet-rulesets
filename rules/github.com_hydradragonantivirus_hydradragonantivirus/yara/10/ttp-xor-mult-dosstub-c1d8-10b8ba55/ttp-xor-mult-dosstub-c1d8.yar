rule TTP_XOR_MULT_DOSStub_c1d8 {
  strings:
    $key_c1d8 = { 95 b0 [2] e1 a8 [2] a6 aa [2] e1 bb [2] af b7 [2] a3 bd [2] b4 b6 [2] af f8 [2] 92 }

  condition:
    any of them
}