rule TTP_XOR_MULT_DOSStub_ccb7 {
  strings:
    $key_ccb7 = { 98 df [2] ec c7 [2] ab c5 [2] ec d4 [2] a2 d8 [2] ae d2 [2] b9 d9 [2] a2 97 [2] 9f }

  condition:
    any of them
}