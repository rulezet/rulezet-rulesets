rule TTP_XOR_MULT_DOSStub_d148 {
  strings:
    $key_d148 = { 85 20 [2] f1 38 [2] b6 3a [2] f1 2b [2] bf 27 [2] b3 2d [2] a4 26 [2] bf 68 [2] 82 }

  condition:
    any of them
}