rule TTP_XOR_MULT_DOSStub_d8fb {
  strings:
    $key_d8fb = { 8c 93 [2] f8 8b [2] bf 89 [2] f8 98 [2] b6 94 [2] ba 9e [2] ad 95 [2] b6 db [2] 8b }

  condition:
    any of them
}