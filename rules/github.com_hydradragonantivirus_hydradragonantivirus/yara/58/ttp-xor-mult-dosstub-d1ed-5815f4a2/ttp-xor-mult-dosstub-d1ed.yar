rule TTP_XOR_MULT_DOSStub_d1ed {
  strings:
    $key_d1ed = { 85 85 [2] f1 9d [2] b6 9f [2] f1 8e [2] bf 82 [2] b3 88 [2] a4 83 [2] bf cd [2] 82 }

  condition:
    any of them
}