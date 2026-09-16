rule TTP_XOR_MULT_DOSStub_60fb {
  strings:
    $key_60fb = { 34 93 [2] 40 8b [2] 07 89 [2] 40 98 [2] 0e 94 [2] 02 9e [2] 15 95 [2] 0e db [2] 33 }

  condition:
    any of them
}