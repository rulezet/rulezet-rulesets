rule TTP_XOR_MULT_DOSStub_d177 {
  strings:
    $key_d177 = { 85 1f [2] f1 07 [2] b6 05 [2] f1 14 [2] bf 18 [2] b3 12 [2] a4 19 [2] bf 57 [2] 82 }

  condition:
    any of them
}