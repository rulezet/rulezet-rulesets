rule TTP_XOR_MULT_DOSStub_d6a2 {
  strings:
    $key_d6a2 = { 82 ca [2] f6 d2 [2] b1 d0 [2] f6 c1 [2] b8 cd [2] b4 c7 [2] a3 cc [2] b8 82 [2] 85 }

  condition:
    any of them
}