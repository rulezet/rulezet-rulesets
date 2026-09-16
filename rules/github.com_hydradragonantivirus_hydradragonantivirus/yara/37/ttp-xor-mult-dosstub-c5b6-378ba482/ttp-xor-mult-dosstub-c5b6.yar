rule TTP_XOR_MULT_DOSStub_c5b6 {
  strings:
    $key_c5b6 = { 91 de [2] e5 c6 [2] a2 c4 [2] e5 d5 [2] ab d9 [2] a7 d3 [2] b0 d8 [2] ab 96 [2] 96 }

  condition:
    any of them
}