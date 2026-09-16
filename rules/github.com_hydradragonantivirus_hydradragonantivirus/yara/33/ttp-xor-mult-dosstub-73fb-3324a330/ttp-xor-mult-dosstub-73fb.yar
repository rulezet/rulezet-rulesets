rule TTP_XOR_MULT_DOSStub_73fb {
  strings:
    $key_73fb = { 27 93 [2] 53 8b [2] 14 89 [2] 53 98 [2] 1d 94 [2] 11 9e [2] 06 95 [2] 1d db [2] 20 }

  condition:
    any of them
}