rule TTP_XOR_MULT_DOSStub_f5d5 {
  strings:
    $key_f5d5 = { a1 bd [2] d5 a5 [2] 92 a7 [2] d5 b6 [2] 9b ba [2] 97 b0 [2] 80 bb [2] 9b f5 [2] a6 }

  condition:
    any of them
}