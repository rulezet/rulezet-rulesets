rule TTP_XOR_MULT_DOSStub_95fb {
  strings:
    $key_95fb = { c1 93 [2] b5 8b [2] f2 89 [2] b5 98 [2] fb 94 [2] f7 9e [2] e0 95 [2] fb db [2] c6 }

  condition:
    any of them
}