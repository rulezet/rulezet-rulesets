rule TTP_XOR_MULT_DOSStub_15d3 {
  strings:
    $key_15d3 = { 41 bb [2] 35 a3 [2] 72 a1 [2] 35 b0 [2] 7b bc [2] 77 b6 [2] 60 bd [2] 7b f3 [2] 46 }

  condition:
    any of them
}