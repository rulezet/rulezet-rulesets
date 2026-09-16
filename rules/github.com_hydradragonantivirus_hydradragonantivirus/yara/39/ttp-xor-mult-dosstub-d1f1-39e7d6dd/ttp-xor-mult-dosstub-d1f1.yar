rule TTP_XOR_MULT_DOSStub_d1f1 {
  strings:
    $key_d1f1 = { 85 99 [2] f1 81 [2] b6 83 [2] f1 92 [2] bf 9e [2] b3 94 [2] a4 9f [2] bf d1 [2] 82 }

  condition:
    any of them
}