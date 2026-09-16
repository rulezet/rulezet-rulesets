rule TTP_XOR_MULT_DOSStub_d1e9 {
  strings:
    $key_d1e9 = { 85 81 [2] f1 99 [2] b6 9b [2] f1 8a [2] bf 86 [2] b3 8c [2] a4 87 [2] bf c9 [2] 82 }

  condition:
    any of them
}