rule TTP_XOR_MULT_DOSStub_10fb {
  strings:
    $key_10fb = { 44 93 [2] 30 8b [2] 77 89 [2] 30 98 [2] 7e 94 [2] 72 9e [2] 65 95 [2] 7e db [2] 43 }

  condition:
    any of them
}