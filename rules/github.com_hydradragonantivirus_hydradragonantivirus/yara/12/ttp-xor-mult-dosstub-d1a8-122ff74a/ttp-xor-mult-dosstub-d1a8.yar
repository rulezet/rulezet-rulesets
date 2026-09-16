rule TTP_XOR_MULT_DOSStub_d1a8 {
  strings:
    $key_d1a8 = { 85 c0 [2] f1 d8 [2] b6 da [2] f1 cb [2] bf c7 [2] b3 cd [2] a4 c6 [2] bf 88 [2] 82 }

  condition:
    any of them
}