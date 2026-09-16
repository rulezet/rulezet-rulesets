rule TTP_XOR_MULT_DOSStub_91fb {
  strings:
    $key_91fb = { c5 93 [2] b1 8b [2] f6 89 [2] b1 98 [2] ff 94 [2] f3 9e [2] e4 95 [2] ff db [2] c2 }

  condition:
    any of them
}