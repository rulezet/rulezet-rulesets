rule TTP_XOR_MULT_DOSStub_d6a9 {
  strings:
    $key_d6a9 = { 82 c1 [2] f6 d9 [2] b1 db [2] f6 ca [2] b8 c6 [2] b4 cc [2] a3 c7 [2] b8 89 [2] 85 }

  condition:
    any of them
}