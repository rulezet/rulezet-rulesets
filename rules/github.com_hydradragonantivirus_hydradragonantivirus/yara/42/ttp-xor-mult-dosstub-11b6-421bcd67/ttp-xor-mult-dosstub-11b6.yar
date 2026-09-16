rule TTP_XOR_MULT_DOSStub_11b6 {
  strings:
    $key_11b6 = { 45 de [2] 31 c6 [2] 76 c4 [2] 31 d5 [2] 7f d9 [2] 73 d3 [2] 64 d8 [2] 7f 96 [2] 42 }

  condition:
    any of them
}