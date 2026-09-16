rule TTP_XOR_MULT_DOSStub_d1a5 {
  strings:
    $key_d1a5 = { 85 cd [2] f1 d5 [2] b6 d7 [2] f1 c6 [2] bf ca [2] b3 c0 [2] a4 cb [2] bf 85 [2] 82 }

  condition:
    any of them
}