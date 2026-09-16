rule TTP_XOR_MULT_DOSStub_55fb {
  strings:
    $key_55fb = { 01 93 [2] 75 8b [2] 32 89 [2] 75 98 [2] 3b 94 [2] 37 9e [2] 20 95 [2] 3b db [2] 06 }

  condition:
    any of them
}