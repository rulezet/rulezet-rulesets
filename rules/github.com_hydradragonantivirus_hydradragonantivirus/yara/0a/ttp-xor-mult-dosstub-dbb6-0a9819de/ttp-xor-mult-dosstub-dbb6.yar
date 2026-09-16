rule TTP_XOR_MULT_DOSStub_dbb6 {
  strings:
    $key_dbb6 = { 8f de [2] fb c6 [2] bc c4 [2] fb d5 [2] b5 d9 [2] b9 d3 [2] ae d8 [2] b5 96 [2] 88 }

  condition:
    any of them
}