rule TTP_XOR_MULT_DOSStub_d1eb {
  strings:
    $key_d1eb = { 85 83 [2] f1 9b [2] b6 99 [2] f1 88 [2] bf 84 [2] b3 8e [2] a4 85 [2] bf cb [2] 82 }

  condition:
    any of them
}