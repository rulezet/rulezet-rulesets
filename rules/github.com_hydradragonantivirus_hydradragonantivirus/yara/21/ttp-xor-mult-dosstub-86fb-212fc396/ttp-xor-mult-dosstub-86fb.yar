rule TTP_XOR_MULT_DOSStub_86fb {
  strings:
    $key_86fb = { d2 93 [2] a6 8b [2] e1 89 [2] a6 98 [2] e8 94 [2] e4 9e [2] f3 95 [2] e8 db [2] d5 }

  condition:
    any of them
}