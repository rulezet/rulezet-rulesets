rule TTP_XOR_MULT_DOSStub_46fb {
  strings:
    $key_46fb = { 12 93 [2] 66 8b [2] 21 89 [2] 66 98 [2] 28 94 [2] 24 9e [2] 33 95 [2] 28 db [2] 15 }

  condition:
    any of them
}