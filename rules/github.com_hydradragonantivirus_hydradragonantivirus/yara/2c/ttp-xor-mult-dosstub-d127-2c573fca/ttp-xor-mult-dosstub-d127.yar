rule TTP_XOR_MULT_DOSStub_d127 {
  strings:
    $key_d127 = { 85 4f [2] f1 57 [2] b6 55 [2] f1 44 [2] bf 48 [2] b3 42 [2] a4 49 [2] bf 07 [2] 82 }

  condition:
    any of them
}