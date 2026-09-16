rule TTP_XOR_MULT_DOSStub_d102 {
  strings:
    $key_d102 = { 85 6a [2] f1 72 [2] b6 70 [2] f1 61 [2] bf 6d [2] b3 67 [2] a4 6c [2] bf 22 [2] 82 }

  condition:
    any of them
}