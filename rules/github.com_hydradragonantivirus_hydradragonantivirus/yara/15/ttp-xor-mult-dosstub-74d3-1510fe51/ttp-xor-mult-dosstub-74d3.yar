rule TTP_XOR_MULT_DOSStub_74d3 {
  strings:
    $key_74d3 = { 20 bb [2] 54 a3 [2] 13 a1 [2] 54 b0 [2] 1a bc [2] 16 b6 [2] 01 bd [2] 1a f3 [2] 27 }

  condition:
    any of them
}