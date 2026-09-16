rule TTP_XOR_MULT_DOSStub_45fb {
  strings:
    $key_45fb = { 11 93 [2] 65 8b [2] 22 89 [2] 65 98 [2] 2b 94 [2] 27 9e [2] 30 95 [2] 2b db [2] 16 }

  condition:
    any of them
}