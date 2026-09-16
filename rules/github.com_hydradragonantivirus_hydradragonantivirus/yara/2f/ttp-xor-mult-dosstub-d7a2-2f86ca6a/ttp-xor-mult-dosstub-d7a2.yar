rule TTP_XOR_MULT_DOSStub_d7a2 {
  strings:
    $key_d7a2 = { 83 ca [2] f7 d2 [2] b0 d0 [2] f7 c1 [2] b9 cd [2] b5 c7 [2] a2 cc [2] b9 82 [2] 84 }

  condition:
    any of them
}