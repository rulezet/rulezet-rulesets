rule TTP_XOR_MULT_DOSStub_d1a2 {
  strings:
    $key_d1a2 = { 85 ca [2] f1 d2 [2] b6 d0 [2] f1 c1 [2] bf cd [2] b3 c7 [2] a4 cc [2] bf 82 [2] 82 }

  condition:
    any of them
}