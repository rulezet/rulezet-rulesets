rule TTP_XOR_MULT_DOSStub_c4d5 {
  strings:
    $key_c4d5 = { 90 bd [2] e4 a5 [2] a3 a7 [2] e4 b6 [2] aa ba [2] a6 b0 [2] b1 bb [2] aa f5 [2] 97 }

  condition:
    any of them
}