rule TTP_XOR_MULT_DOSStub_d11e {
  strings:
    $key_d11e = { 85 76 [2] f1 6e [2] b6 6c [2] f1 7d [2] bf 71 [2] b3 7b [2] a4 70 [2] bf 3e [2] 82 }

  condition:
    any of them
}