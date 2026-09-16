rule TTP_XOR_MULT_DOSStub_d7b2 {
  strings:
    $key_d7b2 = { 83 da [2] f7 c2 [2] b0 c0 [2] f7 d1 [2] b9 dd [2] b5 d7 [2] a2 dc [2] b9 92 [2] 84 }

  condition:
    any of them
}