rule TTP_XOR_MULT_DOSStub_d134 {
  strings:
    $key_d134 = { 85 5c [2] f1 44 [2] b6 46 [2] f1 57 [2] bf 5b [2] b3 51 [2] a4 5a [2] bf 14 [2] 82 }

  condition:
    any of them
}