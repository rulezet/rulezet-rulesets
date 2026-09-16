rule TTP_XOR_MULT_DOSStub_d1fb {
  strings:
    $key_d1fb = { 85 93 [2] f1 8b [2] b6 89 [2] f1 98 [2] bf 94 [2] b3 9e [2] a4 95 [2] bf db [2] 82 }

  condition:
    any of them
}