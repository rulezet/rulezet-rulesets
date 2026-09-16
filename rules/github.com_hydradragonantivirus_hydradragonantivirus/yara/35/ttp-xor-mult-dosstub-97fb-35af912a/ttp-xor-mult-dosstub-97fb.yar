rule TTP_XOR_MULT_DOSStub_97fb {
  strings:
    $key_97fb = { c3 93 [2] b7 8b [2] f0 89 [2] b7 98 [2] f9 94 [2] f5 9e [2] e2 95 [2] f9 db [2] c4 }

  condition:
    any of them
}