rule TTP_XOR_MULT_DOSStub_40fb {
  strings:
    $key_40fb = { 14 93 [2] 60 8b [2] 27 89 [2] 60 98 [2] 2e 94 [2] 22 9e [2] 35 95 [2] 2e db [2] 13 }

  condition:
    any of them
}