rule TTP_XOR_MULT_DOSStub_d143 {
  strings:
    $key_d143 = { 85 2b [2] f1 33 [2] b6 31 [2] f1 20 [2] bf 2c [2] b3 26 [2] a4 2d [2] bf 63 [2] 82 }

  condition:
    any of them
}