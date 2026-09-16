rule TTP_XOR_MULT_DOSStub_f7d5 {
  strings:
    $key_f7d5 = { a3 bd [2] d7 a5 [2] 90 a7 [2] d7 b6 [2] 99 ba [2] 95 b0 [2] 82 bb [2] 99 f5 [2] a4 }

  condition:
    any of them
}