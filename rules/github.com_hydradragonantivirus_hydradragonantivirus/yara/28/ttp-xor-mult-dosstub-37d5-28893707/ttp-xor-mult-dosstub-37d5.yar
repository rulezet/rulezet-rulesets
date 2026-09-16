rule TTP_XOR_MULT_DOSStub_37d5 {
  strings:
    $key_37d5 = { 63 bd [2] 17 a5 [2] 50 a7 [2] 17 b6 [2] 59 ba [2] 55 b0 [2] 42 bb [2] 59 f5 [2] 64 }

  condition:
    any of them
}