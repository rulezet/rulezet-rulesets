rule TTP_XOR_MULT_DOSStub_d165 {
  strings:
    $key_d165 = { 85 0d [2] f1 15 [2] b6 17 [2] f1 06 [2] bf 0a [2] b3 00 [2] a4 0b [2] bf 45 [2] 82 }

  condition:
    any of them
}