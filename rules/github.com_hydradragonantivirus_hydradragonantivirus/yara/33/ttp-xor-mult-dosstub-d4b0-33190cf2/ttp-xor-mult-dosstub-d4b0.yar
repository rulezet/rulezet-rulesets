rule TTP_XOR_MULT_DOSStub_d4b0 {
  strings:
    $key_d4b0 = { 80 d8 [2] f4 c0 [2] b3 c2 [2] f4 d3 [2] ba df [2] b6 d5 [2] a1 de [2] ba 90 [2] 87 }

  condition:
    any of them
}