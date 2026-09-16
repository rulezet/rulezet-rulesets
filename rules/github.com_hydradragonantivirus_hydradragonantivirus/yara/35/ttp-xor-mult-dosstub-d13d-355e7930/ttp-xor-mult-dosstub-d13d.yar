rule TTP_XOR_MULT_DOSStub_d13d {
  strings:
    $key_d13d = { 85 55 [2] f1 4d [2] b6 4f [2] f1 5e [2] bf 52 [2] b3 58 [2] a4 53 [2] bf 1d [2] 82 }

  condition:
    any of them
}