rule TTP_XOR_MULT_DOSStub_d14e {
  strings:
    $key_d14e = { 85 26 [2] f1 3e [2] b6 3c [2] f1 2d [2] bf 21 [2] b3 2b [2] a4 20 [2] bf 6e [2] 82 }

  condition:
    any of them
}