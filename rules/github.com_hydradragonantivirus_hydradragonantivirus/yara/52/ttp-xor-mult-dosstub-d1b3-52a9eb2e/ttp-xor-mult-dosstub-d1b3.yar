rule TTP_XOR_MULT_DOSStub_d1b3 {
  strings:
    $key_d1b3 = { 85 db [2] f1 c3 [2] b6 c1 [2] f1 d0 [2] bf dc [2] b3 d6 [2] a4 dd [2] bf 93 [2] 82 }

  condition:
    any of them
}