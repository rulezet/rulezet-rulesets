rule TTP_XOR_MULT_DOSStub_77fb {
  strings:
    $key_77fb = { 23 93 [2] 57 8b [2] 10 89 [2] 57 98 [2] 19 94 [2] 15 9e [2] 02 95 [2] 19 db [2] 24 }

  condition:
    any of them
}