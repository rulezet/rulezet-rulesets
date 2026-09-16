rule TTP_XOR_MULT_DOSStub_30fb {
  strings:
    $key_30fb = { 64 93 [2] 10 8b [2] 57 89 [2] 10 98 [2] 5e 94 [2] 52 9e [2] 45 95 [2] 5e db [2] 63 }

  condition:
    any of them
}