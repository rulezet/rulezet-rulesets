rule TTP_XOR_MULT_DOSStub_d1f2 {
  strings:
    $key_d1f2 = { 85 9a [2] f1 82 [2] b6 80 [2] f1 91 [2] bf 9d [2] b3 97 [2] a4 9c [2] bf d2 [2] 82 }

  condition:
    any of them
}