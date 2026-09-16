rule TTP_XOR_MULT_DOSStub_c6d8 {
  strings:
    $key_c6d8 = { 92 b0 [2] e6 a8 [2] a1 aa [2] e6 bb [2] a8 b7 [2] a4 bd [2] b3 b6 [2] a8 f8 [2] 95 }

  condition:
    any of them
}