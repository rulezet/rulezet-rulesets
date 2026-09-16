rule TTP_XOR_MULT_DOSStub_ccb6 {
  strings:
    $key_ccb6 = { 98 de [2] ec c6 [2] ab c4 [2] ec d5 [2] a2 d9 [2] ae d3 [2] b9 d8 [2] a2 96 [2] 9f }

  condition:
    any of them
}