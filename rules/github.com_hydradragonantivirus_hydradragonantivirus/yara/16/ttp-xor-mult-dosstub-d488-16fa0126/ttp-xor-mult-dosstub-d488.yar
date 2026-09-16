rule TTP_XOR_MULT_DOSStub_d488 {
  strings:
    $key_d488 = { 80 e0 [2] f4 f8 [2] b3 fa [2] f4 eb [2] ba e7 [2] b6 ed [2] a1 e6 [2] ba a8 [2] 87 }

  condition:
    any of them
}