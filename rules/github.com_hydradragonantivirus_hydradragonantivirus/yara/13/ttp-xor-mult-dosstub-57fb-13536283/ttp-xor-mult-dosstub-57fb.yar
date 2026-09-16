rule TTP_XOR_MULT_DOSStub_57fb {
  strings:
    $key_57fb = { 03 93 [2] 77 8b [2] 30 89 [2] 77 98 [2] 39 94 [2] 35 9e [2] 22 95 [2] 39 db [2] 04 }

  condition:
    any of them
}