rule TTP_XOR_MULT_DOSStub_d1e3 {
  strings:
    $key_d1e3 = { 85 8b [2] f1 93 [2] b6 91 [2] f1 80 [2] bf 8c [2] b3 86 [2] a4 8d [2] bf c3 [2] 82 }

  condition:
    any of them
}