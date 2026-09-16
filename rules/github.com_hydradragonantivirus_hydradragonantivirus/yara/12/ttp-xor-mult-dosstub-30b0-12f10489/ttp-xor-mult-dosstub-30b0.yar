rule TTP_XOR_MULT_DOSStub_30b0 {
  strings:
    $key_30b0 = { 64 d8 [2] 10 c0 [2] 57 c2 [2] 10 d3 [2] 5e df [2] 52 d5 [2] 45 de [2] 5e 90 [2] 63 }

  condition:
    any of them
}