rule TTP_XOR_MULT_DOSStub_37fb {
  strings:
    $key_37fb = { 63 93 [2] 17 8b [2] 50 89 [2] 17 98 [2] 59 94 [2] 55 9e [2] 42 95 [2] 59 db [2] 64 }

  condition:
    any of them
}