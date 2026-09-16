rule TTP_XOR_MULT_DOSStub_e6fb {
  strings:
    $key_e6fb = { b2 93 [2] c6 8b [2] 81 89 [2] c6 98 [2] 88 94 [2] 84 9e [2] 93 95 [2] 88 db [2] b5 }

  condition:
    any of them
}