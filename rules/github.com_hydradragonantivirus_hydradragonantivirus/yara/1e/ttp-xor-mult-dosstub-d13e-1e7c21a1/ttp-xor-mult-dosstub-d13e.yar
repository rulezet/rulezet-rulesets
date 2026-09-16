rule TTP_XOR_MULT_DOSStub_d13e {
  strings:
    $key_d13e = { 85 56 [2] f1 4e [2] b6 4c [2] f1 5d [2] bf 51 [2] b3 5b [2] a4 50 [2] bf 1e [2] 82 }

  condition:
    any of them
}