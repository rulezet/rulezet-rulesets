rule TTP_XOR_MULT_DOSStub_c3b6 {
  strings:
    $key_c3b6 = { 97 de [2] e3 c6 [2] a4 c4 [2] e3 d5 [2] ad d9 [2] a1 d3 [2] b6 d8 [2] ad 96 [2] 90 }

  condition:
    any of them
}