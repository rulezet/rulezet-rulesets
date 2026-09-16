rule TTP_XOR_MULT_DOSStub_d160 {
  strings:
    $key_d160 = { 85 08 [2] f1 10 [2] b6 12 [2] f1 03 [2] bf 0f [2] b3 05 [2] a4 0e [2] bf 40 [2] 82 }

  condition:
    any of them
}