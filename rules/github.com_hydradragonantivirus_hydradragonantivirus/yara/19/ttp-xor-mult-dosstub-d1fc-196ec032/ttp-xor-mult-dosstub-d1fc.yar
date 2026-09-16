rule TTP_XOR_MULT_DOSStub_d1fc {
  strings:
    $key_d1fc = { 85 94 [2] f1 8c [2] b6 8e [2] f1 9f [2] bf 93 [2] b3 99 [2] a4 92 [2] bf dc [2] 82 }

  condition:
    any of them
}