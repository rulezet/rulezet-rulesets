rule TTP_XOR_MULT_DOSStub_d122 {
  strings:
    $key_d122 = { 85 4a [2] f1 52 [2] b6 50 [2] f1 41 [2] bf 4d [2] b3 47 [2] a4 4c [2] bf 02 [2] 82 }

  condition:
    any of them
}