rule TTP_XOR_MULT_DOSStub_55d3 {
  strings:
    $key_55d3 = { 01 bb [2] 75 a3 [2] 32 a1 [2] 75 b0 [2] 3b bc [2] 37 b6 [2] 20 bd [2] 3b f3 [2] 06 }

  condition:
    any of them
}