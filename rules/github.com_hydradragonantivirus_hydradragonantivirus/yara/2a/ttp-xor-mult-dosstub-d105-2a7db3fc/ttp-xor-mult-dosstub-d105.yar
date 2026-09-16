rule TTP_XOR_MULT_DOSStub_d105 {
  strings:
    $key_d105 = { 85 6d [2] f1 75 [2] b6 77 [2] f1 66 [2] bf 6a [2] b3 60 [2] a4 6b [2] bf 25 [2] 82 }

  condition:
    any of them
}