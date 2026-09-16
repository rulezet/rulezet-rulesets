rule TTP_XOR_MULT_DOSStub_d152 {
  strings:
    $key_d152 = { 85 3a [2] f1 22 [2] b6 20 [2] f1 31 [2] bf 3d [2] b3 37 [2] a4 3c [2] bf 72 [2] 82 }

  condition:
    any of them
}