rule TTP_XOR_MULT_DOSStub_75d3 {
  strings:
    $key_75d3 = { 21 bb [2] 55 a3 [2] 12 a1 [2] 55 b0 [2] 1b bc [2] 17 b6 [2] 00 bd [2] 1b f3 [2] 26 }

  condition:
    any of them
}