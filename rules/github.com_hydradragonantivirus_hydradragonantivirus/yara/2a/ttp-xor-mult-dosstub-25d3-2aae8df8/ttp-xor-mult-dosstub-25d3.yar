rule TTP_XOR_MULT_DOSStub_25d3 {
  strings:
    $key_25d3 = { 71 bb [2] 05 a3 [2] 42 a1 [2] 05 b0 [2] 4b bc [2] 47 b6 [2] 50 bd [2] 4b f3 [2] 76 }

  condition:
    any of them
}