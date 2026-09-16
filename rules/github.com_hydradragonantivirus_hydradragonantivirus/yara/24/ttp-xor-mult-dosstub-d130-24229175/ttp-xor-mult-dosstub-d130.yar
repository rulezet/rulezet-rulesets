rule TTP_XOR_MULT_DOSStub_d130 {
  strings:
    $key_d130 = { 85 58 [2] f1 40 [2] b6 42 [2] f1 53 [2] bf 5f [2] b3 55 [2] a4 5e [2] bf 10 [2] 82 }

  condition:
    any of them
}