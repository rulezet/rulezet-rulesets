rule TTP_XOR_MULT_DOSStub_d7b4 {
  strings:
    $key_d7b4 = { 83 dc [2] f7 c4 [2] b0 c6 [2] f7 d7 [2] b9 db [2] b5 d1 [2] a2 da [2] b9 94 [2] 84 }

  condition:
    any of them
}