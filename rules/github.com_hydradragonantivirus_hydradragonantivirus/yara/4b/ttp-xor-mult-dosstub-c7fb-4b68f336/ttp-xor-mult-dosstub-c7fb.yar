rule TTP_XOR_MULT_DOSStub_c7fb {
  strings:
    $key_c7fb = { 93 93 [2] e7 8b [2] a0 89 [2] e7 98 [2] a9 94 [2] a5 9e [2] b2 95 [2] a9 db [2] 94 }

  condition:
    any of them
}