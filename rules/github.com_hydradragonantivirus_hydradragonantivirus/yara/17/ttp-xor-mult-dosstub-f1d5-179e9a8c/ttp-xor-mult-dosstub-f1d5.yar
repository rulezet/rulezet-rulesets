rule TTP_XOR_MULT_DOSStub_f1d5 {
  strings:
    $key_f1d5 = { a5 bd [2] d1 a5 [2] 96 a7 [2] d1 b6 [2] 9f ba [2] 93 b0 [2] 84 bb [2] 9f f5 [2] a2 }

  condition:
    any of them
}