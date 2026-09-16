rule TTP_XOR_MULT_DOSStub_f4fb {
  strings:
    $key_f4fb = { a0 93 [2] d4 8b [2] 93 89 [2] d4 98 [2] 9a 94 [2] 96 9e [2] 81 95 [2] 9a db [2] a7 }

  condition:
    any of them
}