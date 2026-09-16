rule TTP_XOR_MULT_DOSStub_d116 {
  strings:
    $key_d116 = { 85 7e [2] f1 66 [2] b6 64 [2] f1 75 [2] bf 79 [2] b3 73 [2] a4 78 [2] bf 36 [2] 82 }

  condition:
    any of them
}