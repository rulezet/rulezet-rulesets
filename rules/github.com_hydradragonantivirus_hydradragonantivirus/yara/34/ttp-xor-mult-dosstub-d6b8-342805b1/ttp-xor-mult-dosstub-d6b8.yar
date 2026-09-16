rule TTP_XOR_MULT_DOSStub_d6b8 {
  strings:
    $key_d6b8 = { 82 d0 [2] f6 c8 [2] b1 ca [2] f6 db [2] b8 d7 [2] b4 dd [2] a3 d6 [2] b8 98 [2] 85 }

  condition:
    any of them
}