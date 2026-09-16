rule TTP_XOR_MULT_DOSStub_e4d3 {
  strings:
    $key_e4d3 = { b0 bb [2] c4 a3 [2] 83 a1 [2] c4 b0 [2] 8a bc [2] 86 b6 [2] 91 bd [2] 8a f3 [2] b7 }

  condition:
    any of them
}