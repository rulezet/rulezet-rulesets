rule TTP_XOR_MULT_DOSStub_6ab6 {
  strings:
    $key_6ab6 = { 3e de [2] 4a c6 [2] 0d c4 [2] 4a d5 [2] 04 d9 [2] 08 d3 [2] 1f d8 [2] 04 96 [2] 39 }

  condition:
    any of them
}