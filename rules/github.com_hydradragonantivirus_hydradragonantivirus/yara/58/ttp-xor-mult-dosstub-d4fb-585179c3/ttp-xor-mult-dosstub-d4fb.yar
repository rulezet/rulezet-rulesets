rule TTP_XOR_MULT_DOSStub_d4fb {
  strings:
    $key_d4fb = { 80 93 [2] f4 8b [2] b3 89 [2] f4 98 [2] ba 94 [2] b6 9e [2] a1 95 [2] ba db [2] 87 }

  condition:
    any of them
}