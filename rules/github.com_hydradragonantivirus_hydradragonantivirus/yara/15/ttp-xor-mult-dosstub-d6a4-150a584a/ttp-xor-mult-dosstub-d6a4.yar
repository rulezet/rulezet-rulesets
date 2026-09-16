rule TTP_XOR_MULT_DOSStub_d6a4 {
  strings:
    $key_d6a4 = { 82 cc [2] f6 d4 [2] b1 d6 [2] f6 c7 [2] b8 cb [2] b4 c1 [2] a3 ca [2] b8 84 [2] 85 }

  condition:
    any of them
}