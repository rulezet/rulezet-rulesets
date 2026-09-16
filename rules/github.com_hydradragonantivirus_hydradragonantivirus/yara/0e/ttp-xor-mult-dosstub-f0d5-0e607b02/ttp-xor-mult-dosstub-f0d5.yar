rule TTP_XOR_MULT_DOSStub_f0d5 {
  strings:
    $key_f0d5 = { a4 bd [2] d0 a5 [2] 97 a7 [2] d0 b6 [2] 9e ba [2] 92 b0 [2] 85 bb [2] 9e f5 [2] a3 }

  condition:
    any of them
}