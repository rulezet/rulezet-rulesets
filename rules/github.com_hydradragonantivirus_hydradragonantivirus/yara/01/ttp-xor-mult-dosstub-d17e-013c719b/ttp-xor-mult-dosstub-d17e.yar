rule TTP_XOR_MULT_DOSStub_d17e {
  strings:
    $key_d17e = { 85 16 [2] f1 0e [2] b6 0c [2] f1 1d [2] bf 11 [2] b3 1b [2] a4 10 [2] bf 5e [2] 82 }

  condition:
    any of them
}