rule TTP_XOR_MULT_DOSStub_d6b5 {
  strings:
    $key_d6b5 = { 82 dd [2] f6 c5 [2] b1 c7 [2] f6 d6 [2] b8 da [2] b4 d0 [2] a3 db [2] b8 95 [2] 85 }

  condition:
    any of them
}