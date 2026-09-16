rule TTP_XOR_MULT_DOSStub_ccb4 {
  strings:
    $key_ccb4 = { 98 dc [2] ec c4 [2] ab c6 [2] ec d7 [2] a2 db [2] ae d1 [2] b9 da [2] a2 94 [2] 9f }

  condition:
    any of them
}