rule TTP_XOR_MULT_DOSStub_d15d {
  strings:
    $key_d15d = { 85 35 [2] f1 2d [2] b6 2f [2] f1 3e [2] bf 32 [2] b3 38 [2] a4 33 [2] bf 7d [2] 82 }

  condition:
    any of them
}