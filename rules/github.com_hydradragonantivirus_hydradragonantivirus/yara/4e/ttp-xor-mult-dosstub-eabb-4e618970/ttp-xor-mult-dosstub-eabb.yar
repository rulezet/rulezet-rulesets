rule TTP_XOR_MULT_DOSStub_eabb {
  strings:
    $key_eabb = { be d3 [2] ca cb [2] 8d c9 [2] ca d8 [2] 84 d4 [2] 88 de [2] 9f d5 [2] 84 9b [2] b9 }

  condition:
    any of them
}