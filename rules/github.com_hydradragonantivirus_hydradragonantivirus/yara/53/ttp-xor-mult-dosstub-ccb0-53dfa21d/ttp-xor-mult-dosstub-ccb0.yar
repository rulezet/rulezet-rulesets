rule TTP_XOR_MULT_DOSStub_ccb0 {
  strings:
    $key_ccb0 = { 98 d8 [2] ec c0 [2] ab c2 [2] ec d3 [2] a2 df [2] ae d5 [2] b9 de [2] a2 90 [2] 9f }

  condition:
    any of them
}