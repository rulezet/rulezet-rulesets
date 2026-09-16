rule TTP_XOR_MULT_DOSStub_d6b3 {
  strings:
    $key_d6b3 = { 82 db [2] f6 c3 [2] b1 c1 [2] f6 d0 [2] b8 dc [2] b4 d6 [2] a3 dd [2] b8 93 [2] 85 }

  condition:
    any of them
}