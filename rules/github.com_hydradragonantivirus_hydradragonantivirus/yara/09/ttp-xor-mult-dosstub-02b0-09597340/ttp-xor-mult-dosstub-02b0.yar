rule TTP_XOR_MULT_DOSStub_02b0 {
  strings:
    $key_02b0 = { 56 d8 [2] 22 c0 [2] 65 c2 [2] 22 d3 [2] 6c df [2] 60 d5 [2] 77 de [2] 6c 90 [2] 51 }

  condition:
    any of them
}