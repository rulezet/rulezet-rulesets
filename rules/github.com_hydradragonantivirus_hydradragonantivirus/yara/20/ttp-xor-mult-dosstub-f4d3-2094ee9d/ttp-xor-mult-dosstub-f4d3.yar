rule TTP_XOR_MULT_DOSStub_f4d3 {
  strings:
    $key_f4d3 = { a0 bb [2] d4 a3 [2] 93 a1 [2] d4 b0 [2] 9a bc [2] 96 b6 [2] 81 bd [2] 9a f3 [2] a7 }

  condition:
    any of them
}