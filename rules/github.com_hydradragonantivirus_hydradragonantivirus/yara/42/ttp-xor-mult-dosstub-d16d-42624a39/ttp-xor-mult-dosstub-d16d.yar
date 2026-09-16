rule TTP_XOR_MULT_DOSStub_d16d {
  strings:
    $key_d16d = { 85 05 [2] f1 1d [2] b6 1f [2] f1 0e [2] bf 02 [2] b3 08 [2] a4 03 [2] bf 4d [2] 82 }

  condition:
    any of them
}