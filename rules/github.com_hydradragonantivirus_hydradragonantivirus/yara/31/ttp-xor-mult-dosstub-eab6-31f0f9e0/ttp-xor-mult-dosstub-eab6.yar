rule TTP_XOR_MULT_DOSStub_eab6 {
  strings:
    $key_eab6 = { be de [2] ca c6 [2] 8d c4 [2] ca d5 [2] 84 d9 [2] 88 d3 [2] 9f d8 [2] 84 96 [2] b9 }

  condition:
    any of them
}