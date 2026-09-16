rule TTP_XOR_MULT_DOSStub_24d3 {
  strings:
    $key_24d3 = { 70 bb [2] 04 a3 [2] 43 a1 [2] 04 b0 [2] 4a bc [2] 46 b6 [2] 51 bd [2] 4a f3 [2] 77 }

  condition:
    any of them
}