rule TTP_XOR_MULT_DOSStub_d15f {
  strings:
    $key_d15f = { 85 37 [2] f1 2f [2] b6 2d [2] f1 3c [2] bf 30 [2] b3 3a [2] a4 31 [2] bf 7f [2] 82 }

  condition:
    any of them
}