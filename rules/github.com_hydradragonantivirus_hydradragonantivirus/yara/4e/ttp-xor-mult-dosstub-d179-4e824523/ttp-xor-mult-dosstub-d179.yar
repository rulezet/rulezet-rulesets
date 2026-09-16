rule TTP_XOR_MULT_DOSStub_d179 {
  strings:
    $key_d179 = { 85 11 [2] f1 09 [2] b6 0b [2] f1 1a [2] bf 16 [2] b3 1c [2] a4 17 [2] bf 59 [2] 82 }

  condition:
    any of them
}