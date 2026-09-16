rule TTP_XOR_MULT_DOSStub_54d3 {
  strings:
    $key_54d3 = { 00 bb [2] 74 a3 [2] 33 a1 [2] 74 b0 [2] 3a bc [2] 36 b6 [2] 21 bd [2] 3a f3 [2] 07 }

  condition:
    any of them
}