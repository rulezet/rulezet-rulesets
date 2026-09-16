rule TTP_XOR_MULT_DOSStub_62b0 {
  strings:
    $key_62b0 = { 36 d8 [2] 42 c0 [2] 05 c2 [2] 42 d3 [2] 0c df [2] 00 d5 [2] 17 de [2] 0c 90 [2] 31 }

  condition:
    any of them
}