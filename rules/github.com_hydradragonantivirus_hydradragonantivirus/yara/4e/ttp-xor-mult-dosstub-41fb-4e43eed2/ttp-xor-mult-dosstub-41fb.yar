rule TTP_XOR_MULT_DOSStub_41fb {
  strings:
    $key_41fb = { 15 93 [2] 61 8b [2] 26 89 [2] 61 98 [2] 2f 94 [2] 23 9e [2] 34 95 [2] 2f db [2] 12 }

  condition:
    any of them
}