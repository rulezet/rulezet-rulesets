rule TTP_XOR_MULT_DOSStub_44d3 {
  strings:
    $key_44d3 = { 10 bb [2] 64 a3 [2] 23 a1 [2] 64 b0 [2] 2a bc [2] 26 b6 [2] 31 bd [2] 2a f3 [2] 17 }

  condition:
    any of them
}