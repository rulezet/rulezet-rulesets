rule TTP_XOR_MULT_DOSStub_f5fb {
  strings:
    $key_f5fb = { a1 93 [2] d5 8b [2] 92 89 [2] d5 98 [2] 9b 94 [2] 97 9e [2] 80 95 [2] 9b db [2] a6 }

  condition:
    any of them
}