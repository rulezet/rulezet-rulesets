rule TTP_XOR_MULT_DOSStub_64d3 {
  strings:
    $key_64d3 = { 30 bb [2] 44 a3 [2] 03 a1 [2] 44 b0 [2] 0a bc [2] 06 b6 [2] 11 bd [2] 0a f3 [2] 37 }

  condition:
    any of them
}