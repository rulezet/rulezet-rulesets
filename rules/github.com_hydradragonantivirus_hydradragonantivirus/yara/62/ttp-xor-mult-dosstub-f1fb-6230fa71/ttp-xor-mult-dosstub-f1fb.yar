rule TTP_XOR_MULT_DOSStub_f1fb {
  strings:
    $key_f1fb = { a5 93 [2] d1 8b [2] 96 89 [2] d1 98 [2] 9f 94 [2] 93 9e [2] 84 95 [2] 9f db [2] a2 }

  condition:
    any of them
}