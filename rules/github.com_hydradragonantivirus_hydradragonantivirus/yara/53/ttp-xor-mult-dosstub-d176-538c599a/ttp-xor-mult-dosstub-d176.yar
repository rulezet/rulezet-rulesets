rule TTP_XOR_MULT_DOSStub_d176 {
  strings:
    $key_d176 = { 85 1e [2] f1 06 [2] b6 04 [2] f1 15 [2] bf 19 [2] b3 13 [2] a4 18 [2] bf 56 [2] 82 }

  condition:
    any of them
}