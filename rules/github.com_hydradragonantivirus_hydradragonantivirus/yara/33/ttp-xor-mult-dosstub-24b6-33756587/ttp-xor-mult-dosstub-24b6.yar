rule TTP_XOR_MULT_DOSStub_24b6 {
  strings:
    $key_24b6 = { 70 de [2] 04 c6 [2] 43 c4 [2] 04 d5 [2] 4a d9 [2] 46 d3 [2] 51 d8 [2] 4a 96 [2] 77 }

  condition:
    any of them
}