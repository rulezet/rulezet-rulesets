rule TTP_XOR_MULT_DOSStub_d161 {
  strings:
    $key_d161 = { 85 09 [2] f1 11 [2] b6 13 [2] f1 02 [2] bf 0e [2] b3 04 [2] a4 0f [2] bf 41 [2] 82 }

  condition:
    any of them
}