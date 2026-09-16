rule TTP_XOR_MULT_DOSStub_d4d3 {
  strings:
    $key_d4d3 = { 80 bb [2] f4 a3 [2] b3 a1 [2] f4 b0 [2] ba bc [2] b6 b6 [2] a1 bd [2] ba f3 [2] 87 }

  condition:
    any of them
}