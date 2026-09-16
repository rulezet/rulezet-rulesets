rule TTP_XOR_MULT_DOSStub_d168 {
  strings:
    $key_d168 = { 85 00 [2] f1 18 [2] b6 1a [2] f1 0b [2] bf 07 [2] b3 0d [2] a4 06 [2] bf 48 [2] 82 }

  condition:
    any of them
}