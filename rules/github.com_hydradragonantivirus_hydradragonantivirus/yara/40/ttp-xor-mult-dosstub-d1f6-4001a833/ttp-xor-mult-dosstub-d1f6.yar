rule TTP_XOR_MULT_DOSStub_d1f6 {
  strings:
    $key_d1f6 = { 85 9e [2] f1 86 [2] b6 84 [2] f1 95 [2] bf 99 [2] b3 93 [2] a4 98 [2] bf d6 [2] 82 }

  condition:
    any of them
}