rule TTP_XOR_MULT_DOSStub_d141 {
  strings:
    $key_d141 = { 85 29 [2] f1 31 [2] b6 33 [2] f1 22 [2] bf 2e [2] b3 24 [2] a4 2f [2] bf 61 [2] 82 }

  condition:
    any of them
}