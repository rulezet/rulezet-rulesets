rule TTP_XOR_MULT_DOSStub_63fb {
  strings:
    $key_63fb = { 37 93 [2] 43 8b [2] 04 89 [2] 43 98 [2] 0d 94 [2] 01 9e [2] 16 95 [2] 0d db [2] 30 }

  condition:
    any of them
}