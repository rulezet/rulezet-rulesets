rule TTP_XOR_MULT_DOSStub_d16e {
  strings:
    $key_d16e = { 85 06 [2] f1 1e [2] b6 1c [2] f1 0d [2] bf 01 [2] b3 0b [2] a4 00 [2] bf 4e [2] 82 }

  condition:
    any of them
}