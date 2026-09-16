rule TTP_XOR_MULT_DOSStub_d3c6 {
  strings:
    $key_d3c6 = { 87 ae [2] f3 b6 [2] b4 b4 [2] f3 a5 [2] bd a9 [2] b1 a3 [2] a6 a8 [2] bd e6 [2] 80 }

  condition:
    any of them
}