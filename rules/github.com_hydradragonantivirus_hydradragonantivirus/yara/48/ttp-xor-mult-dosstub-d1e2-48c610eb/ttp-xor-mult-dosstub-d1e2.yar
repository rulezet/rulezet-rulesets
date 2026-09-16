rule TTP_XOR_MULT_DOSStub_d1e2 {
  strings:
    $key_d1e2 = { 85 8a [2] f1 92 [2] b6 90 [2] f1 81 [2] bf 8d [2] b3 87 [2] a4 8c [2] bf c2 [2] 82 }

  condition:
    any of them
}