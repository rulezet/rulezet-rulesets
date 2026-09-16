rule TTP_XOR_MULT_DOSStub_d157 {
  strings:
    $key_d157 = { 85 3f [2] f1 27 [2] b6 25 [2] f1 34 [2] bf 38 [2] b3 32 [2] a4 39 [2] bf 77 [2] 82 }

  condition:
    any of them
}