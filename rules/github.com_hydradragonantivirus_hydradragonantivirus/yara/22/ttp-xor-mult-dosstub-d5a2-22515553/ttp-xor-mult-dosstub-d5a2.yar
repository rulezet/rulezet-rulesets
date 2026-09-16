rule TTP_XOR_MULT_DOSStub_d5a2 {
  strings:
    $key_d5a2 = { 81 ca [2] f5 d2 [2] b2 d0 [2] f5 c1 [2] bb cd [2] b7 c7 [2] a0 cc [2] bb 82 [2] 86 }

  condition:
    any of them
}