rule TTP_XOR_MULT_DOSStub_c7d8 {
  strings:
    $key_c7d8 = { 93 b0 [2] e7 a8 [2] a0 aa [2] e7 bb [2] a9 b7 [2] a5 bd [2] b2 b6 [2] a9 f8 [2] 94 }

  condition:
    any of them
}