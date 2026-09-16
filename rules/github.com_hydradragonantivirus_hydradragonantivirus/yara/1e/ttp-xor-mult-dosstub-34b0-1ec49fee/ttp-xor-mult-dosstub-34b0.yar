rule TTP_XOR_MULT_DOSStub_34b0 {
  strings:
    $key_34b0 = { 60 d8 [2] 14 c0 [2] 53 c2 [2] 14 d3 [2] 5a df [2] 56 d5 [2] 41 de [2] 5a 90 [2] 67 }

  condition:
    any of them
}