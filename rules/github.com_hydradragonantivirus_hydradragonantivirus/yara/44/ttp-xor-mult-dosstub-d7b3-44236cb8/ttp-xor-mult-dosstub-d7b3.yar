rule TTP_XOR_MULT_DOSStub_d7b3 {
  strings:
    $key_d7b3 = { 83 db [2] f7 c3 [2] b0 c1 [2] f7 d0 [2] b9 dc [2] b5 d6 [2] a2 dd [2] b9 93 [2] 84 }

  condition:
    any of them
}