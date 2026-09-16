rule TTP_XOR_MULT_DOSStub_d3b7 {
  strings:
    $key_d3b7 = { 87 df [2] f3 c7 [2] b4 c5 [2] f3 d4 [2] bd d8 [2] b1 d2 [2] a6 d9 [2] bd 97 [2] 80 }

  condition:
    any of them
}