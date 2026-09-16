rule TTP_XOR_MULT_DOSStub_94fb {
  strings:
    $key_94fb = { c0 93 [2] b4 8b [2] f3 89 [2] b4 98 [2] fa 94 [2] f6 9e [2] e1 95 [2] fa db [2] c7 }

  condition:
    any of them
}