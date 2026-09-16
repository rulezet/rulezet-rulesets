rule TTP_XOR_MULT_DOSStub_d119 {
  strings:
    $key_d119 = { 85 71 [2] f1 69 [2] b6 6b [2] f1 7a [2] bf 76 [2] b3 7c [2] a4 77 [2] bf 39 [2] 82 }

  condition:
    any of them
}